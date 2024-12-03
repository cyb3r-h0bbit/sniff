from scapy.all import sniff, wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
import binascii
import argparse

def hexdump(pkt):
    """
    This function takes a packet and prints it in both hex and ASCII formats.
    """
    # Convert packet to a raw byte string
    pkt_bytes = bytes(pkt)
    
    # Split the byte string into chunks of 16 bytes
    lines = []
    for i in range(0, len(pkt_bytes), 16):
        # Get 16-byte chunk
        chunk = pkt_bytes[i:i+16]
        hex_chunk = ' '.join([f'{b:02X}' for b in chunk])
        ascii_chunk = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
        
        # Format and combine hex and ASCII
        lines.append(f'{i:04X}  {hex_chunk:<48}  {ascii_chunk}')
    
    # Print the result
    for line in lines:
        print(line)

def packet_callback(pkt, pcap_writer):
    """
    This function processes each packet and displays it in hex and ASCII format, 
    also saves the packet to the pcap file.
    """
    print(f"[==>] Packet Captured: {pkt.summary()}")
    hexdump(pkt)
    
    # Save the packet to the pcap file
    pcap_writer.append(pkt)

def start_sniffing(interface="ens33", output_file="capture.pcap"):
    """
    This function starts sniffing on the given network interface and saves packets 
    to a pcap file.
    """
    print(f"[*] Starting sniffing on {interface}...")
    
    # Create a pcap file writer
    pcap_writer = []
    
    # Capture packets and process them with packet_callback
    sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, pcap_writer), store=0)
    
    # Write all captured packets to a pcap file
    print(f"[*] Saving packets to {output_file}...")
    wrpcap(output_file, pcap_writer)

if __name__ == "__main__":
    # Set up argument parser to accept command-line arguments
    parser = argparse.ArgumentParser(description="Packet Sniffer with Pcap Save")
    parser.add_argument("interface", help="The network interface to sniff on")
    parser.add_argument("-o", "--output", default="capture.pcap", help="Output pcap file (default: capture.pcap)")
    
    # Parse the arguments
    args = parser.parse_args()

    # Start sniffing with the specified interface and output file
    start_sniffing(interface=args.interface, output_file=args.output)
