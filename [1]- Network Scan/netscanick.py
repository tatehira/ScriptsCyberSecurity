import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import srp, Ether, ARP

def scan(ip_range):
    try:
        arp_requests = []
        for ip in ip_range:
            arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            arp_requests.append(arp)

        answered, unanswered = srp(arp_requests, timeout=2, verbose=False)

        print("Endereços IP ativos na rede:")
        for send, receive in answered:
            print(receive.psrc)

    except KeyboardInterrupt:
        print("\nVarredura interrompida pelo usuário.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python netscanick.py <ip_range>")
        print("Exemplo: python netscanick.py 192.168.1.1/24")
    else:
        ip_range = sys.argv[1]
        scan(ip_range)
