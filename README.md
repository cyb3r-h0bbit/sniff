# Network Packet Sniffer (Windows & Linux)
![sniff](https://github.com/user-attachments/assets/220ffeac-02af-4548-a2d2-54f226260d48)

```
 py .\proxy.py Ethernet0
```

![Screenshot 2024-12-11 183130](https://github.com/user-attachments/assets/d79c1c5b-cd90-49d9-bd7f-44d6ff1fe7ef)

A lightweight packet sniffer for **Windows** and **Linux** that captures **Layer 2 (Ethernet)** packets, displaying detailed **hex** and **ASCII** output. It supports sniffing on any network interface and saves packets to a **PCAP** file for analysis.

## Features:
- Cross-platform support: **Windows** (with Npcap) and **Linux**.
- Captures **Layer 2 (Ethernet)** packets.
- Displays **hex** and **ASCII** output for each packet.
- Saves packets to **PCAP** files for analysis.

## Dependencies:
- **Windows**: Requires **Npcap. Scapy**.
- **Linux**: Requires **Scapy**.
