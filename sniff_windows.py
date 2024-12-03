from scapy.all import sniff, wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
import argparse

def hexdump(pkt):
    """
    This function takes a packet and prints it in both hex and ASCII formats.
    """
    pkt_bytes = bytes(pkt)
    lines = []
    for i in range(0, len(pkt_bytes), 16):
        chunk = pkt_bytes[i:i+16]
        hex_chunk = ' '.join([f'{b:02X}' for b in chunk])
        ascii_chunk = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
        lines.append(f'{i:04X}  {hex_chunk:<48}  {ascii_chunk}')
    
    for line in lines:
        print(line)

def packet_callback(pkt, pcap_writer):
    """
    This function processes each packet and displays it in hex and ASCII format, 
    also saves the packet to the pcap file.
    """
    print(f"[==>] Packet Captured: {pkt.summary()}")
    hexdump(pkt)
    pcap_writer.append(pkt)

def start_sniffing(interface="Ethernet0", output_file="capture.pcap"):
    """
    This function starts sniffing on the given network interface and saves packets 
    to a pcap file.
    """
    print(f"[*] Starting sniffing on {interface}...")
    pcap_writer = []
    
    # Sniffing Layer 2 packets
    sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, pcap_writer), store=0, filter="ip")  # You can modify the filter to capture other protocols
    
    print(f"[*] Saving packets to {output_file}...")
    wrpcap(output_file, pcap_writer)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer with Pcap Save")
    parser.add_argument("interface", help="The network interface to sniff on")
    parser.add_argument("-o", "--output", default="capture.pcap", help="Output pcap file (default: capture.pcap)")
    
    args = parser.parse_args()
    start_sniffing(interface=args.interface, output_file=args.output)
