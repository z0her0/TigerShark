# TigerShark - A Python Wrapper for TShark
TigerShark is a Python script that provides a user-friendly interface for interacting with TShark, a network protocol analyzer. It allows you to perform various network analysis tasks, view statistics, and extract information from packet capture (PCAP) files. TigerShark simplifies the use of TShark's command-line capabilities and provides an easy-to-use menu-driven interface.

## Menu Options
- `Get PCAP Info`: This feature provides a comprehensive summary of the capture file's contents. This initial assessment includes details such as the duration of capture, packet counts, and start and end date. This information sets the foundation for any in-depth network analysis. This is always the first thing I check.
- `Get Protocol Hierarchy Statistics`: This feature delivers a detailed breakdown of protocol usage within a PCAP file. This is invaluable for quickly spotting unusual protocol distributions. By presenting a hierarchical view of protocol interactions, it aids in identifying anomalies and prioritizing areas for deeper forensic investigation. This is always the second thing I check.
- `Get Expert Info`: This extracts and presents 'expert chat' messages from pcap files. These messages highlight potential issues and anomalies in the network traffic, such as malformed packets, unusual transmissions, or potential security flags. This feature provides a streamlined way to access these insights, helping incident responders quickly identify and focus on potential areas of concern within the PCAP. This is always the third thing I check.
- `Search Protocol`: Enables detailed investigation into specific protocols within pcap files, for targeted analysis in incident response scenarios.
- `Enumerate Hostnames`: This feature extracts hostnames across various communication layers. By analyzing frame-level data, it identifies patterns that may reveal default Windows hostnames. Within DHCP traffic analysis, this specifically looks for instances where a device is assigned an IP address. By capturing these hostnames during the IP address assignment phase, we effectively map network participants and can aid in identifying unauthorized or new devices connecting to the network. NetBIOS Name Service (NBNS) queries are parsed to uncover hostnames used in local area networks. Kerberos authentication traffic is examined for service principal names, which include hostnames indicative of access to network services. This feature also targets authentication events that involve NT LAN Manager (NTLM) Security Support Provider (SSP), a common authentication mechanism in Windows networks. When users or devices access shared resources, SMB-based authentication processes are initiated. The "ntlmssp.auth.hostname" filter extracts hostnames from these authentication events. This feature also analyzes network browsing via the Browser Protocol, capturing active machine hostnames and roles within the network. For inter-process communications, Distributed Computing Environment / Remote Procedure Calls (DCERPC) traffic is scrutinized, particularly focusing on the Netlogon protocol, to identify participating hostnames. By targeting hostname details in Netlogon messages, we effectively capture the hostnames of client machines interacting with domain controllers. Additionally, it processes Link-Local Multicast Name Resolution (LLMNR) and Connectionless Lightweight Directory Access Protocol (cLDAP) traffic, helpful in scenarios like name resolution in small networks and domain membership checks. Each protocol's focus contributes to a comprehensive picture of network structure, highlighting active devices.
- `Enumerate Users`: This operates by dissecting user-relevant data from several key network protocols. The Security Account Manager Remote Protocol (SAMR) is utilized to extract user names from network account management activities, such as account creation or modification. This also leverages Lightweight Directory Access Protocol (LDAP) to retrieve user account details during directory service queries, often occurring in user validation or access scenarios. In Kerberos traffic, user logins and ticket-granting events are analyzed, providing insights into user authentications across network services. Furthermore, Server Message Block (SMB) protocol analysis reveals user names engaged in internal network activities like file sharing or accessing remote services. By aggregating user information from these varied sources, we effectively pinpoint user activities and interactions within the network, aiding in identifying normal operational patterns as well as potential unauthorized or anomalous user behaviors.
- `Follow TCP Stream`: This feature allows for the reconstruction of the entire conversation between two network endpoints within a TCP stream. It's useful in piecing together the sequence of events in a network session, providing a complete context for forensic analysis. You can use this to uncover hidden data transfers, trace steps of an intrusion, or fully understand the scope of a malware's network communication.
- `Follow HTTP Stream`: This feature allows for the reconstruction of the entire conversation between two network endpoints within a HTTP stream. Unlike TCP streams, HTTP stream analysis allows you to view the decompressed contents of gzip-encoded files, which is essential for examining web content that has been compressed for transmission.
- `Show Packets`: Displays network packets based on user-defined criteria, allowing the ability to focus on potentially malicious or anomalous traffic.
- `Look For Beacons`: This feature identifies beacon-like traffic patterns, commonly associated with malware communication or data exfiltration. Additionally, it utilizes matplotlib to launch a visual plot, representing the traffic patterns graphically. This visual representation is helpful in quickly identifying regular, suspicious communication intervals, making it easier to spot and investigate potential command and control (C2) communications or automated malware traffic.
- `Analyze Web Traffic`: This feature is specifically designed for an in-depth forensic analysis of web traffic. This focuses on HTTP requests and responses, while also including the initial TLS handshake (specifically, the client HELLO message). This aspect is crucial in HTTPS traffic analysis, as the server name indicated in the client HELLO can often be the only forensic evidence in encrypted web traffic. By capturing and analyzing this initial handshake, you can uncover the identity of the server presenting the certificate, thus gaining insights into potentially malicious web traffic that would otherwise be obscured by encryption.
- `Get WHOIS Data`: This feature performs WHOIS lookups for unique destination IPs found in the PCAP. In addition to this, it conducts DNSBL (DNS-Based Blackhole List) lookups and compares the IPs against a list from 'hxxps://blackip.ustc.edu[.]cn/list.php'. Also, the output deliberately excludes IPs from top CDN providers like AWS, Akamai, Google, and Azure, as these are often benign and can clutter the analysis with false positives. This approach is crucial for accurately identifying known malicious sources and verifying if the destination IPs are listed in global threat intelligence databases. It provides an understanding of the network's security landscape, focusing on genuinely suspicious IPs while filtering out the noise typically associated with high-traffic CDN providers.
- `Find TCP Stream Index In Frame`: Locates and displays the TCP stream index for a specified frame.
- `Search For Domain in DNS`: Analyzes DNS queries for specific domains to uncover DNS-based attacks and malicious domain activities.
- `Look For Failed Connection Attempts`: Detects failed TCP connections, which could indicate attempts to reach command and control (C2) servers or other malicious endpoints.
- `Get User Agents`: Extracts and analyzes HTTP user agents from network traffic, providing insights into client software and potential spoofing.
- `Detect Signs Of ARP Poisoning`: Searches for indications of ARP poisoning, a common tactic in Man-in-the-Middle (MITM) attacks.
- `Detect Spambot Activity`: This feature facilitates spambot activity detection by displaying network traffic on ports: 25, 465, and 587. It provides a straightforward presentation of packets from these ports, enabling you to manually examine and identify potential spambot behavior. This capability is crucial for uncovering phishing, spam dissemination, or botnet C2 communications.
- `Use Any Display Filter`: Applies custom TShark display filters, allowing for tailored investigation focused on specific security concerns.  Use `Search For Valid Tshark Display Filters` to help you find display filters.
- `Search For Valid Tshark Display Filters`: This feature offers an interactive way to discover relevant TShark display filters for specific network protocols. When you input a protocol, such as 'dns', the function executes TShark to pull a comprehensive list of all available display filters. It then processes this list to present only those filters pertinent to the entered protocol, specifically focusing on filters with string fields. This approach aids in pinpointing precise filters for detailed network analysis, enabling you to repeatedly input different protocols to find corresponding filters. This functionality significantly streamlines the process of crafting targeted TShark commands for specific investigative needs in network forensics and incident response.
- `View Statistics`: This feature taps into the extensive statistical capabilities of Wireshark/TShark and presents key statistics such as conversation tables, endpoint details, protocol hierarchies, and server response times. This integration allows you to quickly identify unusual patterns, including spikes in traffic, abnormal protocol distributions, and interactions with suspicious IPs. The strength of this feature lies in its ability to harness Wireshark/TShark's sophisticated data processing. Essentially, "View Statistics" serves as a conduit, channeling the advanced analytic power of Wireshark/TShark into a user-friendly and accessible format.
- `Follow Flows`: This feature focuses on analyzing communication flows between network endpoints. This functionality is particularly useful in scenarios where tracking the broader context of network traffic is crucial. Unlike following a TCP stream, which concentrates on the packet-level details of a single TCP connection, "Follow Flows" offers a macro perspective, allowing you to observe patterns and relationships across different connections and protocols. This broader viewpoint is helpful in detecting and identifying coordinated activities among multiple endpoints, which might be missed when focusing solely on individual TCP streams.
- `Lookup DCERPC Service Method Abuse Info`: This feature provides an interactive interface for retrieving detailed information about various DCERPC services. It allows you to look up specific DCERPC services and operation numbers (opnums) from a comprehensive dictionary that contains mappings to a specific opnum's methods, notes, attack tactics, attack types, and indicators of compromise (IOCs). You can list all available DCERPC services, get detailed information about a particular service/opnum, or search across all services for specific opnums or definitions. This is particularly valuable for incident responders who need to quickly access detailed information about DCERPC services and associated opnums, aiding in the analysis of network traffic and investigation of potential security incidents involving DCERPC protocols.
- `Help Menu`: Offers assistance and guidance on using the tool effectively, enhancing user experience and efficiency in incident response tasks.
- `Clear Screen`: Provides a clean working environment by clearing the console screen, aiding in maintaining focus during analysis.
- `Quit`: Allows the user to exit the program safely and efficiently, ensuring a smooth end to the analysis session.

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
   ```
   git clone https://github.com/z0her0/TigerShark.git
   ```

2. Navigate to the TigerShark root directory:
   ```
   cd TigerShark
   ```

3. Create a virtual environment:
   ```
   python3 -m venv venv_tigershark
   ```

4. Activate the virtual environment:
   ```
   source venv_tigershark/bin/activate
   ```

5. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

6. Run the main program `tiger_shark.py`:
   ```
   python3 src/tiger_shark.py
   ```

7. When prompted, provide path to PCAP file (point this to where your PCAP file exists):
   ```
   ../pcaps/name_of_pcap.pcap
   ```

8. Press ENTER to display the main menu.
