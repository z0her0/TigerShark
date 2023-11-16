# TigerShark - A Python Wrapper for TShark
TigerShark is a Python script that provides a user-friendly interface for interacting with TShark, a network protocol analyzer. It allows you to perform various network analysis tasks, view statistics, and extract information from packet capture (PCAP) files. TigerShark simplifies the use of TShark's command-line capabilities and provides an easy-to-use menu-driven interface.

## Features
- `DCERPC Service Abuse Analysis`: Provides detailed insights into potential abuses of specific DCERPC services and methods.
- `Host Enumeration`: Enumerates and lists hosts involved in various network protocols, offering insights into network structure.
- `User Enumeration`: Identifies and lists user accounts engaged in different network protocols, useful for understanding user activities.
- `Protocol Hierarchy Statistics`: Generates input/output protocol hierarchy statistics from pcap files for network traffic analysis.
- `Expert Diagnostics`: Extracts 'expert chat' diagnostic messages from pcap files, aiding in identifying network issues.
- `Failed Connection Identification`: Detects and provides details on failed TCP connection attempts, helpful in troubleshooting network issues.
- `WHOIS IP Lookup`: Performs WHOIS lookups for unique destination IP addresses found in network traffic, useful for identifying potential threats.
- `ARP Poisoning Detection`: Searches for signs of ARP poisoning attacks, enhancing network security analysis.
- `HTTP User Agent Analysis`: Extracts and counts occurrences of HTTP user agents, offering insights into client software used on the network.
- `Web Traffic Extraction`: Retrieves web traffic information, useful for general malicious web activity.
- `Beacon-Like Traffic Pattern Identification`: Identifies beacon-like traffic patterns, aiding in detecting regular communication intervals often used by malware.
- `Custom Display Filter Application`: Applies user-specified TShark display filters to customize network traffic analysis.
- `DNS Query Analysis`: Searches DNS queries or responses for specific domains, assisting in domain-specific network traffic investigation.
- `TCP and HTTP Stream Analysis`: Follows and displays contents of specified TCP and HTTP streams, useful for detailed packet-level analysis.
- `Packet Display Based on User Choice`: Offers options to display all network packets or those filtered by a specific protocol.
- `Comprehensive Network Statistics`: Provides various network statistics such as conversations, server response times, and more, for a detailed understanding of network behavior.
- `Verbose Information Processing`: Reads and processes verbose information based on user-selected protocols, offering detailed packet insights.

## Usage
1. Run `tiger_shark.py` and provide the path to a PCAP file when prompted.
2. Choose from a variety of options in the interactive menu to perform specific tasks or analyses on the PCAP file.

## Requirements
- Python 3.9+
    - see `requirements.txt`
- Mac or Linux.  Support for Windows is coming soon.
- WireShark (installed to default location)

## Installation

1. Clone the TigerShark repository to your local machine:
   ```bash
   git clone https://github.com/zer0hero-rl/TigerShark.git
   ```

2. Navigate to the TigerShark directory:
   ```bash
   cd TigerShark
   ```

3. Run the `tiger_shark.py` script:
   ```bash
   python src/tiger_shark.py
   ```
