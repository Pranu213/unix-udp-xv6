# C-Shark - The Command-Line Packet Predator

A comprehensive packet sniffer implementing both Phase 1 and Phase 2 requirements with complete layer-by-layer packet analysis.

## Requirements
- Linux operating system
- libpcap development headers (`sudo apt install libpcap-dev` on Ubuntu/Debian)
- GCC compiler with C standard libraries
- Root privileges for packet capture

## Build & Run
```bash
make clean && make
sudo ./cshark
```

## Features Implemented

### Phase 1: Basic Packet Capture 
- **Task 1.1: Device Discovery** - Automatically scans and lists all available network interfaces
- **Task 1.2: Main Menu & Packet Capture** - Interactive menu with live packet capture and display

### Phase 2: Layer-by-Layer Analysis 
- **Task 2.1: Layer 2 (Ethernet)** - MAC addresses, EtherType identification (IPv4, IPv6, ARP)
- **Task 2.2: Layer 3 (Network)** - Complete parsing for:
  - IPv4: Source/Dest IP, Protocol, TTL, Packet ID, Total Length, Header Length, Flags
  - IPv6: Source/Dest IP, Next Header, Hop Limit, Traffic Class, Flow Label, Payload Length
  - ARP: Operation type, Sender/Target IPs and MACs, Hardware/Protocol types and lengths
- **Task 2.3: Layer 4 (Transport)** - Full parsing for:
  - TCP: Ports (with common service identification), Sequence/ACK numbers, Flags, Window, Checksum, Header Length
  - UDP: Ports (with common service identification), Length, Checksum
- **Task 2.4: Layer 7 (Payload)** - Application protocol identification (HTTP, HTTPS, DNS) and hex+ASCII dump of first 64 bytes

### Phase 3: Precision Hunting - Advanced Filtering
- **Protocol-based Filtering**: Support for HTTP, HTTPS, DNS, ARP, TCP, UDP
- **User-friendly Filter Menu**: Easy selection of common protocols
- **Custom Filter Options**: Advanced filtering by IP addresses and ports

### Phase 4: The Packet Aquarium - Session Storage  
- **Session Management**: Automatic cleanup of previous sessions
- **Memory Management**: Proper allocation/deallocation with 10,000 packet capacity
- **Session State Tracking**: Active session monitoring and validation

### Phase 5: Digital Forensics Lab - Deep Inspection
- **Packet List Summary**: Tabular view of all captured packets with basic info
- **Detailed Packet Analysis**: Comprehensive layer-by-layer breakdown
- **Complete Hex Dumps**: Full packet content in hex+ASCII format
- **Interactive Selection**: Choose specific packets for in-depth analysis

## Additional Features
- **Graceful Signal Handling**: Ctrl+C returns to menu, Ctrl+D exits cleanly
- **Professional Output**: Clean, formatted displays matching network analysis tools

## Usage Example
The application provides:
1. **Interface Discovery**: Lists all available network interfaces
2. **Main Menu Options**:
   - **Option 1**: Start sniffing all packets (live display with storage)
   - **Option 2**: Start sniffing with filters (HTTP, HTTPS, DNS, ARP, TCP, UDP, or custom)
   - **Option 3**: Inspect last session (view packet summary and detailed analysis)
   - **Option 4**: Clear packet storage
   - **Option 5**: Exit the application

## Sample Output
```
[C-Shark] The Command-Line Packet Predator
==============================================
[C-Shark] Searching for available interfaces... Found!

1. wlan0
2. any (Pseudo-device that captures on all interfaces)
3. lo
4. docker0
...

Select an interface to sniff (1-10): 2
[C-Shark] Interface 'any' selected. What's next?

Main Menu:
1. Start Sniffing (All Packets)
2. Start Sniffing (With Filters)
3. Inspect Last Session (stored packets)
4. Clear Packet Store
5. Exit C-Shark
```

## Controls
- **Ctrl+C**: Stop packet capture and return to main menu
- **Ctrl+D**: Exit program cleanly from any point
- **Interactive Menu**: Use numbers 1-5 to navigate options
