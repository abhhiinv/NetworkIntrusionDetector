from scapy.all import IP, TCP, send

target_ip = "192.168.1.1"

print(f"Initiating CIC-IDS2017 Spoofed Scan against {target_ip}...")

# We match the exact signature from your dataset's 5th row:
# A single SYN packet with a hardcoded TCP Window of 253
packet_list = []
for port in range(1, 1000):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S", window=253)
    packet_list.append(pkt)

# Blast the packets onto the network
send(packet_list, verbose=False)

print("Scan complete. Check your NIDS terminal!")