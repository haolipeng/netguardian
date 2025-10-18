#!/usr/bin/env python3
"""
Generate test PCAP files for NetGuardian testing
"""

from scapy.all import *
import sys

def generate_test_traffic(output_file):
    """Generate various types of network traffic for testing"""

    packets = []

    # 1. Normal DNS queries
    print("[+] Generating normal DNS queries...")
    for i in range(10):
        pkt = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=50000+i, dport=53)/ \
              DNS(rd=1, qd=DNSQR(qname=f"example{i}.com"))
        packets.append(pkt)

        # DNS responses
        resp = Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=50000+i)/ \
               DNS(id=0, qr=1, aa=0, rcode=0, qd=DNSQR(qname=f"example{i}.com"), \
                   an=DNSRR(rrname=f"example{i}.com", ttl=300, rdata="93.184.216.34"))
        packets.append(resp)

    # 2. Suspicious DNS queries (potential DGA)
    print("[+] Generating suspicious DNS queries...")
    for i in range(5):
        pkt = Ether()/IP(src="192.168.1.200", dst="8.8.8.8")/UDP(sport=60000+i, dport=53)/ \
              DNS(rd=1, qd=DNSQR(qname=f"asdfghjklqwerty{i}.ru"))
        packets.append(pkt)

        # NXDOMAIN responses
        resp = Ether()/IP(src="8.8.8.8", dst="192.168.1.200")/UDP(sport=53, dport=60000+i)/ \
               DNS(id=0, qr=1, rcode=3, qd=DNSQR(qname=f"asdfghjklqwerty{i}.ru"))
        packets.append(resp)

    # 3. HTTP GET requests
    print("[+] Generating HTTP traffic...")
    for i in range(3):
        syn = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=40000+i, dport=80, flags="S", seq=1000+i)
        synack = Ether()/IP(src="93.184.216.34", dst="192.168.1.100")/TCP(sport=80, dport=40000+i, flags="SA", seq=2000+i, ack=1001+i)
        ack = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=40000+i, dport=80, flags="A", seq=1001+i, ack=2001+i)

        packets.extend([syn, synack, ack])

        # HTTP request
        http_req = f"GET /test{i}.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        req = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=40000+i, dport=80, flags="PA", seq=1001+i, ack=2001+i)/Raw(load=http_req)
        packets.append(req)

    # 4. ICMP traffic
    print("[+] Generating ICMP traffic...")
    for i in range(5):
        pkt = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/ICMP(type=8, code=0, id=1234, seq=i)
        packets.append(pkt)

    # 5. UDP traffic (non-DNS)
    print("[+] Generating UDP traffic...")
    for i in range(5):
        pkt = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/UDP(sport=5000+i, dport=6000+i)/Raw(load=b"Test data")
        packets.append(pkt)

    # Write to PCAP file
    print(f"[+] Writing {len(packets)} packets to {output_file}...")
    wrpcap(output_file, packets)
    print(f"[+] PCAP file created successfully!")

    # Print statistics
    print(f"\n[+] Statistics:")
    print(f"    Total packets: {len(packets)}")
    print(f"    DNS packets: {sum(1 for p in packets if DNS in p)}")
    print(f"    HTTP packets: {sum(1 for p in packets if TCP in p and (p[TCP].dport == 80 or p[TCP].sport == 80))}")
    print(f"    ICMP packets: {sum(1 for p in packets if ICMP in p)}")
    print(f"    UDP packets (non-DNS): {sum(1 for p in packets if UDP in p and p[UDP].dport != 53 and p[UDP].sport != 53)}")

if __name__ == "__main__":
    output_file = sys.argv[1] if len(sys.argv) > 1 else "test_traffic.pcap"
    generate_test_traffic(output_file)
