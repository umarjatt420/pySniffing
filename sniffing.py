from scapy.all import *

def packet_handler(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            payload = pkt[TCP].payload
            print(f"Source IP: {src_ip}  Destination IP: {dst_ip}")
            print(f"Source Port: {src_port}  Destination Port: {dst_port}")
            print(f"Payload: {payload}")
        # data = pkt[IP].load
        # print(f"Packet Data: {data}")
        # print(f"Source IP: {src_ip}  Destination IP: {dst_ip}")

# Sniff packets on a network interface
sniff(iface='wlan0', prn=packet_handler, filter='tcp')