import os
# The os module provides a portable way of using operating system dependent functionality
# like reading or writing to the file system, managing paths, etc.

import json
# The json module can parse JSON from strings or files and convert them to Python dictionaries.
# It can also convert Python dictionaries to JSON strings.

import subprocess
# The subprocess module allows you to spawn new processes, connect to their input/output/error pipes,
# and obtain their return codes.

from collections import Counter
# Counter is a dict subclass for counting hashable objects in the collections module.
# It is an unordered collection where elements are stored as dictionary keys and their counts are stored as dictionary values.

from dcerpc_method_abuse_notes import get_dcerpc_info
# Import get_dcerpc_info to retrieve DCERPC service opnums and method names

from make_colorful import Color
# Custom module for adding color to terminal output.
# This needs to be present in the same directory or in the Python path.

from make_helpers import (
    input_prompt,           # Custom function for prompting user input in a standardized way.
    is_valid_interval,      # Custom function for validating if a given value falls within a specified interval.
    is_valid_digit,         # Custom function for checking if a string represents a valid digit.
    is_valid_ipv4_address,  # Custom function for validating IPv4 addresses.
    set_tshark_path,        # Custom function for setting the path to the tshark application.
    get_input_opnum,        # Custom function for validating user input
)

# The make_helpers module contains custom utility functions that are used throughout the script.

# After locating the paths to tshark and capinfo, set_tshark_path() returns these paths, which is then interpreted as
# a tuple. The returned tuple is then unpacked into the variables tshark and capinfo by utilizing a feature called
# tuple unpacking
tshark, capinfo = set_tshark_path()


class TShark:
    """
    This class is meant to serve as an interface for executing Tshark commands and processing their outputs
    with the TShark packet analyzer utility.

    Attributes:
        pcap_file (str): The path to the pcap file to be analyzed.
        proc (subprocess.Popen or None): A handle to the running TShark process (None until the process is started).
    """
    def __init__(self, pcap_file):
        """
        Initializes the TShark instance with the path to a pcap file.

        Args:
            pcap_file (str): The path to the pcap file to be analyzed.

        Raises:
            FileNotFoundError: If the TShark executable is not found on the system.
        """
        self.pcap_file = pcap_file
        self.proc = None

        if not os.path.isfile(tshark):
            raise Exception('Cannot find tshark in ' + tshark)

    def _run_command(self, cmd):
        """
        Helper method to execute a given system command and return its output.

        :param cmd: List of command elements to be executed.
        :return: Standard output from executing the command.
        """
        completed_process = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)
        return completed_process.stdout.decode()

    def pcap_info(self):
        """
        Get PCAP info via capinfos such as capture file comments, packet counts, duration, start and end times,
        data byte rates, and more.
        """
        return self._run_command([capinfo, self.pcap_file])

    def iophs(self):
        """
        Execute the tshark command with options to analyze the protocol hierarchy statistics of a pcap file.

        This method constructs a command to run tshark with the `-qz io,phs` option for quiet output of protocol
        hierarchy statistics and `-r` to specify the pcap file to analyze. It then delegates to `_run_command`
        to execute this command.

        Returns:
            The output of the `_run_command` method which is typically the stdout from the tshark command.
        """
        return self._run_command([tshark, '-qz', 'io,phs', '-r', self.pcap_file])

    def whois_ip(self):
        """
        Perform a WHOIS lookup for unique destination IP addresses found in a pcap file.

        This function reads a pcap file, extracts unique destination IP addresses using tshark,
        and then performs a WHOIS lookup for each unique IP address using the 'whois.cymru.com' service.

        Returns:
            None
        """
        # Use tshark to extract destination IP addresses from the pcap file
        check_tshark_output = self._run_command([tshark, '-r', self.pcap_file, '-T', 'fields', '-e', 'ip.dst'])

        # Split the tshark output into a list of IP addresses
        tshark_dest_ips = check_tshark_output.strip().splitlines()

        # Create a set of unique IP addresses, filtering out empty strings
        unique_ips = set(filter(None, tshark_dest_ips))

        # Perform a WHOIS lookup for each unique IP address and print the results
        for ip in unique_ips:
            # If this hangs, try running this command: `sudo vim /etc/resolv.conf`.  Comment out the current
            # nameserver line.  Add two lines: `nameserver 8.8.8.8`\n`nameserver 8.8.4.4`. Save and exit.
            whois_info = self._run_command(['whois', '-h', 'whois.cymru.com', ip])
            print(whois_info)

    def find_beacons(self):
        """
        Prompts the user for an IPv4 address and an interval frequency to identify potential beaconing behavior in network traffic.

        Beaconing can be characterized by repeated patterns of communication at regular intervals and is often used by
        malware to signal back to a command and control server.

        The user is prompted to enter a specific IPv4 address to investigate, along with a time interval in seconds.
        This method then constructs and executes a tshark command to analyze the PCAP file for patterns that match the
        specified criteria.

        Returns:
            str: The output from tshark command which includes the statistical analysis of the network traffic related
            to the specified IP address and time interval.

        Raises:
            subprocess.CalledProcessError: If the tshark command fails to execute.
        """
        ask_ip = input_prompt(
            "Enter the IPv4 address you wish to look for patterns to determine beacons (Example valid input: 10.10.14.19): ",
            is_valid_ipv4_address
        )
        ask_freq = input_prompt("Enter the interval frequency (Example: for 120 secs intervals, enter 120): ",
                                is_valid_interval)
        return self._run_command([tshark, '-qz',
                                  f'io,stat,{ask_freq},MAX(frame.time_relative)frame.time_relative,ip.addr=={ask_ip},MIN(frame.time_relative)frame.time_relative',
                                  '-r', self.pcap_file])

    def expert_chat(self):
        """
        Executes a tshark command to analyze the pcap file for expert information and
        chat messages. It filters and summarizes the results to display them in a human-readable form.

        The '-qz' option tells tshark to run in quiet mode and to produce statistics.
        'expert,chat' is the particular statistic we want, which analyzes the captured data for
        any expert messages (warnings, errors, and notes) and chat-style messages (like chat protocols).

        :return: A string containing the expert information and chat messages extracted from the pcap file.
        """
        return self._run_command([tshark, '-qz', 'expert,chat', '-r', self.pcap_file])

    def display_filter(self):
        """
        We can use the display_filter method to specify custom fields when analyzing network packets using tshark

        Example: This will generate a tshark command that includes the -T fields -e nbns.name -e nbns.id options:

        Enter a valid display filter: nbns
        Expand the packet layers? yes
        View all packets? no
        Specify custom fields? (Y/N): Y
        Enter one or more custom field options (comma-separated): nbns.name,nbns.id
        """
        get_input = input("Enter a valid display filter: ")
        view_verbose = input("Expand the packet layers? ")
        view_all_pkts = input("View all packets? ")
        custom_fields = input("Specify custom fields? (Y/N): ")

        cmd = [tshark, '-Y', get_input, '-r', self.pcap_file]

        # Check if custom fields should be added
        if custom_fields.lower() == "y":
            # Add the '-T fields' option to the tshark command
            cmd.extend(['-T', 'fields'])

            # Prompt the user to enter one or more custom field options
            custom_field_options = input("Enter one or more custom field options (comma-separated): ")

            # Split the entered options into a list
            custom_fields_list = custom_field_options.split(',')

            # Iterate through the custom fields and add them to the tshark command
            for field in custom_fields_list:
                cmd.extend(['-e', field.strip()])

        # Check if the 'view_verbose' variable is equal to "yes"
        if view_verbose == "yes":
            cmd.append('-V')

        if view_all_pkts == "no":
            how_many_pkts = input("How many packets do you want to see? ")
            cmd.extend(['-c', f"{how_many_pkts}"])

        if view_verbose == "no" and view_all_pkts == "yes":
            cmd.insert(1, '-C')
            cmd.insert(2, 'THunt')

        # Run the command and capture its output
        output = self._run_command(cmd)

        # Check if the user wants to add custom fields
        if custom_fields.lower() == "y":

            # Filter out blank lines using a generator expression
            non_blank_lines = (line for line in output.splitlines() if line.strip())

            # Join the non-blank lines back into a single string to pass to subprocess
            filtered_output = '\n'.join(non_blank_lines)

            # Use subprocess to run the 'sort' command and sort the 'output' data by the first field
            sorted_output = subprocess.run(['sort', '-k', '1,1'], input=filtered_output, stdout=subprocess.PIPE, text=True).stdout

            # Use the 'uniq' command to count unique occurrences and prefix each line with the count
            unique_count_output = subprocess.run(['uniq', '-c'], input=sorted_output, stdout=subprocess.PIPE, text=True).stdout
            return unique_count_output
        else:
            return output

    def get_dcerpc_abuse_info(self):
        # Usage of the function:
        service_name_input = input("Enter the service (e.g., samr, drsuapi, netlogon, lsarpc, srvsvc): ")
        opnum_input = get_input_opnum()

        method, note = get_dcerpc_info(service_name_input, opnum_input)

        if method:
            print(f"{Color.AQUA}Info for {service_name_input} opnum {opnum_input}{Color.END}")
            print(f"{Color.UNDERLINE}Function:{Color.END} {method}")
            print(f"{Color.UNDERLINE}Note:{Color.END} {note}")
        else:
            print(note)

    def failed_connections(self):
        """
        Runs a tshark command to identify failed TCP connection attempts in a PCAP file.

        This method applies a display filter to identify TCP retransmissions where the
        TCP flags are set to 0x0002 (SYN flag). Such patterns are indicative of
        connection attempts where the SYN packet has been retransmitted, suggesting
        that the initial SYN might not have been acknowledged.

        The '-C THunt' option applies a custom tshark profile named 'THunt'. This profile
        contains specific configurations, preferences, and overrides tailored to my
        analysis needs.

        :return: The standard output from the tshark command execution, which includes
        the details of failed TCP connection attempts.
        """
        return self._run_command(
            [tshark, '-C', 'THunt', '-Y', 'tcp.analysis.retransmission and tcp.flags eq 0x0002', '-r', self.pcap_file])

    def arp_thunt(self):
        """
        Execute tshark commands to detect ARP anomalies in a pcap file.

        This method runs two separate tshark commands to check for:
        1. Duplicate ARP address detection
        2. ARP packet storm detection

        It utilizes the pcap file specified by the 'self.pcap_file' attribute.

        Returns:
        tuple: A tuple containing the results from the two tshark command executions.
            The first element corresponds to the duplicate address detection results,
            and the second to the packet storm detection results.
        """
        return self._run_command(
            [tshark, '-Y', 'arp.duplicate-address-detected', '-r', self.pcap_file, '-T', 'fields', '-e',
             'arp.duplicate-address-detected']), \
            self._run_command([tshark, '-Y', 'arp.packet-storm-detected', '-r', self.pcap_file, '-T', 'fields', '-e',
                               'arp.packet-storm-detected'])

    def dns_hunt(self):
        """
        Prompts the user for a domain to search within DNS queries in a PCAP file
        and executes a tshark command with a custom filter to find matches.

        Returns:
            The output from the tshark command execution, which includes details
            of any DNS queries that match the specified domain.
        """
        ask_dns = input("Enter the domain you want to search for here in double quotes: ")
        return self._run_command([tshark, '-C', 'THunt', '-Y', 'dns matches ' + f"{ask_dns}", '-r', self.pcap_file])

    def user_agent(self):
        """
        Extracts and counts occurrences of User Agent strings from a PCAP file.

        This method uses the tshark utility to read the specified PCAP file, filters out
        the HTTP User Agent strings, and then counts the occurrences of each unique User Agent.

        Returns:
            A JSON-formatted string with User Agent strings and their respective counts, sorted by frequency.
        """

        # Extract User Agent strings using tshark
        cmd = [tshark, '-r', self.pcap_file, '-T', 'fields', '-e', 'http.user_agent']
        output = self._run_command(cmd)

        # Clean, split, and count the User Agent strings
        user_agents = output.strip().split('\n')
        user_agent_counts = Counter(user_agents).most_common()
        print("User Agent (by count):")
        return json.dumps(user_agent_counts, indent=2)

    def viewframe_getstream(self):
        """
        Prompt the user to enter a frame number and returns the corresponding TCP stream index from the pcap file.

        This function asks the user to input a frame number, then constructs and runs a Tshark command to extract
        the TCP stream index associated with that frame from the pcap file loaded in the instance.

        Returns:
            list: A list containing the TCP stream index(es) for the given frame number, as returned by the Tshark
            command.
        """
        ask_frame = input("Enter the frame number you'd like to get the tcp stream index for: ")
        return self._run_command(
            [tshark, '-Y', f"frame.number == {ask_frame}", '-r', self.pcap_file, '-T', 'fields', '-e', 'tcp.stream'])

    def web_basic(self):
        """
        This query reveals URLs for HTTP requests, and domain names used in HTTPS or TLS traffic.
        tls.handshake.type == 1 returns us the CLIENT HELLO packets.  tls.handshake.extensions_server_name
        reveals domain names used in HTTPS or TLS traffic by looking at the server serving up the
        certificate during the Client Hello TLS handshake to get a server hostname. The THunt config profile
        has tls.handshake.extensions_server_name as one of the columns, so we will see these results.
        To further reduce noise, I filter out Simple Service Discovery Protocol (SSDP) - this is a protocol
        used to discover plug and play devices and is not associated with normal web traffic.
        """
        print('')
        print(f"{Color.GREEN}Web Traffic:{Color.END}")
        print('')
        return self._run_command(
            [tshark, '-C', 'THunt', '-Y', '(http.request or http.response or tls.handshake.type eq 1) and !(ssdp)',
             '-r', self.pcap_file])

    def tcp_stream(self):
        """
        Prompts the user for a TCP stream index and then returns the ASCII representation
        of that stream from a pcap file using tshark.

        :return: ASCII representation of the requested TCP stream.
        """
        get_tcp_stream_number = input_prompt("Which TCP stream index would you like to see? ", is_valid_digit)
        return self._run_command([tshark, '-qz', f'follow,tcp,ascii,{get_tcp_stream_number}', '-r', self.pcap_file])

    def http_stream(self):
        """
        Prompts the user for an HTTP stream index and then returns the ASCII representation
        of that stream from a pcap file using tshark.

        :return: ASCII representation of the requested HTTP stream.
        """
        get_http_stream_number = input_prompt("Which HTTP stream index would you like to see? ", is_valid_digit)
        return self._run_command([tshark, '-qz', f'follow,http,ascii,{get_http_stream_number}', '-r', self.pcap_file])

    def enum_streams(self):
        """
        Prompts the user for a protocol field to search for within the pcap file. It then
        returns a list of frame numbers, TCP stream indexes, source and destination IPs,
        destination ports, and the values for the requested protocol field.

        :return: Formatted output containing enumerated stream information based on the user's protocol field input.
        """
        ask = input(
            "Which protocol would you like to search for? Examples: x509sat.printableString, http.request.full_uri, dns.qry.name: ")
        print(' ')
        return self._run_command(
            [tshark, '-Y', f"{ask}", '-r', self.pcap_file, '-T', 'fields', '-e', 'frame.number', '-e', 'tcp.stream',
             '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.dstport', '-e', f"{ask}", '-E', 'header=yes'])

    def show_packets(self):
        """
        Interactively display packets from a pcap file based on user's input.

        This function asks the user if they want to display all packets or
        packets from a specific protocol. Based on the response, it calls
        an internal command-running method to fetch and return the appropriate
        packet data from the pcap file.

        Returns:
            str: A formatted string containing the relevant packet data.
        """
        get_proto = input("Show all packets? (yes or no) ")
        print('')
        # If the user doesn't want to show all packets
        if get_proto == "no":
            which_proto = input("Which protocol would you like to see all packets for? ")
            print('')
            # Extract packets for the specified protocol
            return 'All ' + which_proto + ' packets:' + '\n==================================================================\n' + self._run_command(
                [tshark, '-Y', which_proto, '-r', self.pcap_file])

        # If the user wants to show all packets
        elif get_proto == "yes":
            return 'All packets:' + '\n==================================================================\n' + self._run_command(
                [tshark, '-r', self.pcap_file])

    def statistics(self):
        """
        Provides an interface for the user to select a type of statistics to view
        from the PCAP file, such as conversations, server response times, tree statistics,
        or host information. Depending on the user's choice, the corresponding detailed
        statistics for a specific protocol can be displayed.
        """
        which_stats = input(
            f"{Color.LIGHTYELLOW}What type of statistics do you want to view? (conv/hosts/srt/tree): {Color.END}: ")

        def conversations():
            """
            Prompts the user for a specific protocol and then prints the conversations
            statistics for that protocol using TShark.
            """
            ask_protocol = input(
                f"{Color.CYAN}Which protocol would you like to view conversations for? (bluetooth/eth/ip/tcp/usb/wlan){Color.END}: ")
            # Define a dictionary mapping protocol names to TShark commands
            protocol_commands = {
                'bluetooth': ['conv,bluetooth'],
                'eth': ['conv,eth'],
                'ip': ['conv,ip'],
                'tcp': ['conv,tcp'],
                'usb': ['conv,usb'],
                'wlan': ['conv,wlan']
            }
            if ask_protocol in protocol_commands:
                tshark_command = [tshark, '-qz'] + protocol_commands[ask_protocol] + ['-r', self.pcap_file]
                print(self._run_command(tshark_command))
            else:
                return "Unsupported protocol"

        def server_resp_times():
            """
            Prompts the user for a specific protocol and then prints the server response times
            statistics for that protocol using TShark.
            """
            ask_protocol = input(
                f"{Color.GOLD}Which protocol would you like to see server response times for? (icmp/ldap/smb/smb2/srvsvc/drsuapi/lsarpc/netlogon/samr){Color.END}: ")
            protocol_commands = {
                'icmp': ['icmp,srt'],
                'ldap': ['ldap,srt'],
                'smb': ['smb,srt'],
                'smb2': ['smb2,srt'],
                'drsuapi': ['dcerpc,srt,e3514235-4b06-11d1-ab04-00c04fc2dcd2,4.0'],
                'lsarpc': ['dcerpc,srt,12345778-1234-abcd-ef00-0123456789ab,0.0'],
                'netlogon': ['dcerpc,srt,12345678-1234-abcd-ef00-01234567cffb,1.0'],
                'samr': ['dcerpc,srt,12345778-1234-ABCD-EF00-0123456789AC,1.0'],
                'srvsvc': ['dcerpc,srt,4b324fc8-1670-01d3-1278-5a47bf6ee188,3.0']
            }
            if ask_protocol in protocol_commands:
                tshark_command = [tshark, '-qz'] + protocol_commands[ask_protocol] + ['-r', self.pcap_file]
                print(self._run_command(tshark_command))
            else:
                return "Unsupported protocol"

        def tree():
            """
            Prompts the user for a specific protocol and then prints the tree statistics
            for that protocol using TShark.
            """
            ask_protocol = input(
                f"{Color.LIGHTGREEN}Which protocol would you like to see tree statistics for? (dns/ip_hosts/http/http_req/http_srv/plen/ptype){Color.END}: ")
            protocol_commands = {
                'dns': ['dns,tree'],
                'http_req': ['http_req,tree'],
                'http_srv': ['http_srv,tree'],
                'http': ['http,tree'],
                'ip_hosts': ['ip_hosts,tree'],
                'ip_srcdst': ['ip_srcdst,tree'],
                'plen': ['plen,tree'],
                'ptype': ['ptype,tree']
            }
            if ask_protocol in protocol_commands:
                tshark_command = [tshark, '-qz'] + protocol_commands[ask_protocol] + ['-r', self.pcap_file]
                print(self._run_command(tshark_command))
            else:
                return "Unsupported protocol"

        def hosts():
            """
            Prints the host statistics from the PCAP file using TShark.
            """
            tshark_command = [tshark, '-qz', 'hosts,ip', '-r', self.pcap_file]
            print(self._run_command(tshark_command))

        if which_stats == 'conv':
            return conversations()
        elif which_stats == 'srt':
            return server_resp_times()
        elif which_stats == 'tree':
            return tree()
        elif which_stats == 'hosts':
            return hosts()

    def read_verbose(self):
        """
        Prompts the user to choose a network protocol to search within a PCAP file
        and then executes a corresponding tshark command to filter and display
        information related to that protocol from the PCAP file.
        """
        ask_protocol = input(f"{Color.CYAN}Choose a protocol to search{Color.END}: ")
        print('')

        # 'eth' Protocol
        if ask_protocol == "eth":
            # Filter for Ethernet OUI from PCAP file.
            get_eth2 = self._run_command(
                [tshark, '-Y', 'eth', '-r', self.pcap_file, '-T', 'fields', '-e', 'eth.addr.oui_resolved']
            )
            out_eth2 = get_eth2.strip()
            # Use a list comprehension to filter out empty lines before counting
            non_empty_lines = [line for line in out_eth2.split('\n') if line.strip()]
            count_eth2 = Counter(non_empty_lines).most_common()
            return "Eth Addr OUI (by count):" + '\n' + json.dumps(count_eth2, indent=2)

        # 'urlencoded-form' Protocol
        elif ask_protocol == 'urlencoded-form':
            # Extract url-encoded form data
            return self._run_command(
                [tshark, '-Y', 'urlencoded-form', '-r', self.pcap_file, '-T', 'json', '-e', 'urlencoded-form.key', '-e',
                 'urlencoded-form.value']
            )

        # Check if the chosen protocol is 'samr'
        elif ask_protocol == 'samr':

            # Run tshark command to extract SAMR protocol information from the PCAP file
            samr_protocol_output = self._run_command(
                [tshark, '-Y', 'samr', '-r', self.pcap_file, '-Tfields', '-e', 'samr.samr_LookupNames.names']
            )

            # Count occurrences of SAMR LSA queries

            # Using a generator expression to strip whitespace from each line before counting
            # This also avoids creating unnecessary intermediate lists
            counts = Counter(line.strip() for line in samr_protocol_output.split('\n') if line.strip())
            most_common_elements = counts.most_common()
            return f"SAMR LSA queries for: {most_common_elements}"

        # 'http' Protocol
        elif ask_protocol == 'http':
            return self._run_command(
                [tshark, '-Y', 'http.request || http.response', '-r', self.pcap_file, '-Tfields', '-e', 'frame.number',
                 '-e', 'frame.time', '-e', 'ip.src', '-e', 'http.request.full_uri', '-e', 'http.response_for.uri', '-E',
                 'header=y']
            )

        # 'smb' Protocol
        elif ask_protocol == 'smb':
            # NTLMSSP Auth Hostname
            out_smb_ntlmssp = self._run_command(
                [tshark, '-r', self.pcap_file, '-T', 'fields', '-e', 'ntlmssp.auth.hostname']
            )
            hostnames = [hostname for hostname in out_smb_ntlmssp.strip().split('\n') if hostname]
            count_hostnames = Counter(sorted(hostnames)).most_common()

            # NTLMSSP Auth Username
            out_smb_ntlmssp_uname = self._run_command(
                [tshark, '-r', self.pcap_file, '-T', 'fields', '-e', 'ntlmssp.auth.username']
            )
            usernames = [username for username in out_smb_ntlmssp_uname.strip().split('\n') if username]
            count_usernames = Counter(sorted(usernames)).most_common()

            return (
                f"{Color.YELLOW}NTLMSSP Auth Hostname (by count): {Color.END}\n{count_hostnames}\n\n"
                f"{Color.RED}NTLMSSP Auth Username (by count): {Color.END}\n{count_usernames}\n\n"
            )

        # 'smb2' Protocol
        elif ask_protocol == 'smb2':
            # SMB2 Filenames
            smb2_short = self._run_command(
                [tshark, '-Y', 'smb2.filename', '-r', self.pcap_file, '-T', 'fields', '-e', 'smb2.filename']
            )
            filenames = [filename for filename in smb2_short.strip().split('\n') if filename]
            count_filenames = Counter(sorted(filenames)).most_common()

            return (
                f"{Color.RED}SMB2 Filename (by count): {Color.END}\n"
                f"{json.dumps(count_filenames, indent=2)}"
            )

        # 'data-text-lines' Protocol
        elif ask_protocol == 'data-text-lines':
            return self._run_command(
                [tshark, '-Y', 'data-text-lines', '-r', self.pcap_file, '-V', '-O', 'data-text-lines']
            )

        # 'mime_multipart' Protocol
        elif ask_protocol == 'mime_multipart':
            return self._run_command(
                [tshark, '-Y', 'mime_multipart', '-r', self.pcap_file, '-V', '-O', 'mime_multipart']
            )

        # 'dns' Protocol
        elif ask_protocol == 'dns':
            out_dns = self._run_command(
                [tshark, '-Y', 'dns', '-r', self.pcap_file, '-T', 'fields', '-e', 'dns.qry.name']
            )

            # This code takes a string-like object out_dns, cleans it by
            # removing leading and trailing whitespace, splits it into lines, and creates a new list containing
            # only the non-empty lines from the original string. The resulting list contains the cleaned and
            # filtered lines of text.
            dns_queries = [query for query in out_dns.strip().split("\n") if query]

            # The filtered lines (containing valid DNS queries) are stored in the dns_queries list. This list will
            # contain one entry for each valid DNS query found in the original text. The Counter class from the
            # collections module is used to count the occurrences of each unique DNS query in the dns_queries
            # list. The most_common() method is then called on the Counter object, which returns a list of tuples.
            # Each tuple contains a unique DNS query and its count, sorted in descending order by count. This
            # allows you to determine which DNS queries are the most common in the data.
            count_dns = Counter(dns_queries).most_common()
            return f"{Color.BOLD}Most Popular DNS Queries (C2 over DNS?):{Color.END}\n{json.dumps(count_dns, indent=2)}"

        # 'dhcp' Protocol
        elif ask_protocol == 'dhcp':
            """
            Processes the PCAP file to extract hostnames from DHCP traffic.
            Counts the occurrences of each hostname and returns the results in JSON format.
            """
            dhcp_output = self._run_command(
                [tshark, '-Y', 'dhcp', '-r', self.pcap_file, '-T', 'fields', '-e', 'dhcp.option.hostname']
            )
            hostnames = [name for name in dhcp_output.strip().split('\n') if name]
            count_dhcp = Counter(hostnames).most_common()
            print("DHCP Host Name (by count):")
            return json.dumps(count_dhcp, indent=2)

        # 'kerberos' Protocol
        elif ask_protocol == 'kerberos':
            """
            Analyzes Kerberos protocol traffic within the PCAP file to extract user and hostnames
            from Kerberos tickets. It distinguishes between regular usernames and machine accounts
            (which contain a '$'), counts the occurrences, and returns a formatted string containing
            the results.
            """
            tshark_args = [tshark, '-r', self.pcap_file, '-Tfields', '-e', 'kerberos.CNameString']

            cname_string = self._run_command(
                tshark_args + ['-Y', 'kerberos.CNameString and !(kerberos.CNameString contains "$")']
            )
            cname_string_with_dollar = self._run_command(
                tshark_args + ['-Y', 'kerberos.CNameString and (kerberos.CNameString contains "$")']
            )

            kerb_users = [name for name in set(cname_string.strip().split('\n')) if name]
            kerb_hosts = [name for name in set(cname_string_with_dollar.strip().split('\n')) if name]

            return (f'Windows Account Username\n{Counter(kerb_users).most_common()}\n\nHostname\n'
                    f'{Counter(kerb_hosts).most_common()}\n')

        # 'ldap' Protocol
        elif ask_protocol == "ldap":
            return self._run_command([tshark, '-Y', 'ldap.AttributeDescription == "givenName"', '-r', self.pcap_file])

        # 'epm' Protocol
        elif ask_protocol == "epm":
            return self._run_command([tshark, '-Y', 'epm', '-r', self.pcap_file, '-V', '-O', 'epm'])

        # 'tls' Protocol
        elif ask_protocol == "tls":
            # Get TLS extension server name
            tls_server_names = self._run_command([tshark, '-Y', 'tls', '-r', self.pcap_file, '-T', 'fields', '-e',
                                                 'tls.handshake.extensions_server_name']).strip().split('\n')
            tls_server_names = [name for name in tls_server_names if name]

            # Get counts for server names
            counts = Counter(tls_server_names).most_common(20)

            # Get TLS x509sat Certificate
            tls_certs = self._run_command(
                [tshark, '-Y', 'tls', '-r', self.pcap_file, '-T', 'fields', '-e', 'x509sat.printableString']
            ).strip().split('\n')

            tls_certs = [cert for cert in tls_certs if cert]

            # Get counts for certificates
            count_cert = Counter(tls_certs).most_common(20)
            return f"{Color.BOLD}TLS Handshake Extensions Server Name (Top 10):{Color.END}" + '\n' \
                + json.dumps(counts, indent=2) + '\n\n' \
                + f"{Color.BOLD}TLS Handshake Certificate x509sat Printable String(Top 10):{Color.END}" + '\n' \
                + json.dumps(count_cert, indent=2)

        # 'pkix-cert' Protocol
        elif ask_protocol == "pkix-cert":
            return self._run_command(
                [tshark, '-Y', 'pkix-cert.cert', '-r', self.pcap_file, '-T', 'json', '-e', 'x509sat.printableString']
            )

        # 'icmp' Protocol
        elif ask_protocol == "icmp":
            """
            Process ICMP data from a PCAP file based on user input.

            Args:
                ask_protocol (str): User's choice of protocol.

            Returns:
                str: Processed ICMP data.
            """
            # Common tshark arguments shared by all commands
            tshark_args = [tshark, '-r', self.pcap_file, '-t', 'ad']

            # Capture ICMP Echo Requests data
            icmp_req = self._run_command([*tshark_args, '-Y', '(icmp.type == 8) && (icmp.code == 0)'])

            # Capture ICMP Echo Replies data
            icmp_resp = self._run_command([*tshark_args, '-Y', '(icmp[0] == 0) && (icmp[1] == 0)'])

            # Return formatted ICMP data
            return (f"{Color.LIGHTBLUE}ECHO Requests (frame #, time, src ip, dst ip, info):{Color.END}\n{icmp_req}\n"
                    f"{Color.LIGHTGREEN}ECHO replies (frame #, time, src ip, dst ip, info):{Color.END}\n{icmp_resp}")


# The following block will only be executed if this module is run as the main script.
if __name__ == '__main__':
    # This code will not run when the module is imported.
    pass
