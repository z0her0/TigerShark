"""  # pylint: disable=line-too-long
This Python module provides a comprehensive interface to the TShark network protocol analyzer,
enabling detailed analysis and reporting on network packet capture (pcap) files. It includes
classes and methods for performing a variety of network analysis tasks, including enumerating
hosts and users, following TCP and HTTP streams, detecting ARP poisoning, and more.

The TShark class at the core of this module acts as a wrapper around TShark command-line
utilities, offering Pythonic access to its rich feature set. It includes methods for extracting
specific data from pcap files, such as WHOIS information, user agents, beacon-like traffic patterns,
and expert diagnostics. Additionally, the module contains utilities for user input validation and
colorful terminal output to enhance user interaction.

Key Features:
- Interface to interact with TShark for pcap file analysis.
- Methods for extracting specific network protocol information.
- Capabilities to enumerate hosts and users, follow streams, and detect security threats.
- Utilities for user input validation and enhanced terminal output.
"""

import logging
import os  # Operating system interfaces
import subprocess  # Process creation and management
from collections import Counter  # Container for counting hashable objects
from typing import Optional, Dict, List, Tuple, Any, Union

import matplotlib.pyplot as plt
from rich.table import Table
from rich.console import Console

from dcerpc_method_abuse_notes import get_dcerpc_info  # MSRPC to ATT&CK lookup table
from make_colorful import Color, ColorRandomRGB  # Terminal color output utility
from make_helpers import (
    input_prompt,  # Standardized user input prompt
    is_valid_interval,  # Interval validation
    is_valid_digit,  # Digit validation
    is_valid_ipv4_address,  # IPv4 address validation
    set_tshark_path,  # Set the path to the tshark application
    get_input_opnum,  # Get and validate user input
)

# tuple unpacking into the variables tshark and capinfo
tshark, capinfo = set_tshark_path()


class TShark:
    """
    A class to provide an interface to the TShark network protocol analyzer.
    """
    def __init__(self, pcap_file: str) -> None:
        """
        Initializes the TShark class with the specified pcap file.
        """
        self.pcap_file: str = pcap_file
        self.proc: Optional[subprocess.CompletedProcess] = None
        if not os.path.isfile(tshark):
            raise FileNotFoundError('Cannot find tshark in ' + tshark)

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ S༙྇t༙྇a༙྇t༙྇i༙྇c༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    @staticmethod
    def get_dcerpc_abuse_info() -> None:
        """
        Retrieves and prints abuse information for a specified DCERPC service and method.
        """
        service_name_input = input("Enter the service (e.g., samr, drsuapi, netlogon, lsarpc, srvsvc): ")
        opnum_input = get_input_opnum()
        try:
            method, note, attack_ttp, attack_type, ioc = get_dcerpc_info(service_name_input, opnum_input)
            if method:
                print(f"{Color.AQUA}Info for {service_name_input} opnum {opnum_input}:{Color.END}")
                print("")
                print(f"{Color.UNDERLINE}Function{Color.END}: {method}")
                print("")
                print(f"{Color.UNDERLINE}ATT&CK TTP{Color.END}: {attack_ttp}")
                print("")
                print(f"{Color.UNDERLINE}Attack Type{Color.END}: {attack_type}")
                print("")
                print(f"{Color.UNDERLINE}IOC{Color.END}: {ioc}")
                print("")
                print(f"{Color.UNDERLINE}Note{Color.END}: {note}")
                print("")
            else:
                print(note)
        except ValueError as e:
            print(f"Error occurred: {e}")
            method, note, attack_ttp, attack_type, ioc = None, None, None, None, None

    @staticmethod
    def _run_command(cmd: List[str]) -> str:
        """
        Runs a command in a subprocess and returns its output.
        """
        completed_process: subprocess.CompletedProcess = subprocess.run(cmd, stdout=subprocess.PIPE, shell=False, check=False)
        return completed_process.stdout.decode()

    @staticmethod
    def display_results(results: Dict[str, List[Tuple[str, int]]], fields: Dict[str, str]) -> None:
        """
        Displays the results of the tshark command processing in a formatted manner using rich.
        Args:
            results (Dict[str, List[Tuple[str, int]]]): The processed results from tshark commands.
            fields (Dict[str, str]): The fields used for each protocol in the tshark command.
        """
        console = Console()
        for protocol, data in results.items():
            field = fields[protocol]
            # Enhanced table with custom box and header style
            table = Table(title=f"{field}: {protocol}")
            table.add_column("Count", style="bold cyan", justify="right")
            table.add_column(f"{protocol}", style=f"rgb({ColorRandomRGB.random_color()[0]},{ColorRandomRGB.random_color()[1]},{ColorRandomRGB.random_color()[2]})", overflow="fold")
            # Conditional row styling
            for host, count in data:
                style = "bold" if count > 100 else ""
                # table.add_row(str(count), host)
                table.add_row(str(count), host, style=style)
            console.print(table)

    @staticmethod
    def _process_output(output: str) -> List[Tuple[str, int]]:
        """
        Processes the output from a tshark command to sort, remove blank lines, count occurrences, and sort
        based on counts.
        Args:
            output (str): The raw string output from a tshark command.
        Returns:
            List[Tuple[str, int]]: A list of tuples containing the item and its count, sorted by the count.
        """
        sorted_output = [line for line in output.strip().split('\n') if line.strip()]
        return Counter(sorted_output).most_common()

    @staticmethod
    def process_output(output, protocol):
        """
        Processes the output from a tshark command, organizing it by protocol.

        This method takes the raw string output from a tshark command, splits it into lines,
        cleans each line by removing leading and trailing whitespace and tabs, and then counts
        the occurrences of each line. The results are sorted based on these counts in descending order.

        Args:
            output (str): The raw string output from a tshark command.
            protocol (str): The protocol name associated with the output.

        Returns:
            dict: A dictionary where the key is the protocol name and the value is a list of tuples.
                  Each tuple contains a line (str) and its count (int), sorted by the count in descending order.
        """
        # Split the output into lines
        lines = output.strip().split('\n')
        # Remove leading and trailing whitespace and tabs from each line
        cleaned_lines = [line.strip().replace('\t', '') for line in lines if line.strip()]
        sorted_counts = Counter(cleaned_lines).most_common()
        return {protocol: sorted_counts}

    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ S྇t྇a྇t྇i྇c྇ M྇e྇t྇h྇o྇d྇s྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ T༙྇S༙྇h༙྇a༙྇r༙྇k༙྇ C༙྇o༙྇m༙྇m༙྇a༙྇n༙྇d༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def _run_tshark_command(self, options: List[str], display_filter: Optional[str] = None,
                            custom_fields: Optional[str] = None) -> str:
        """
        Runs a TShark command with the specified options, display filter, and custom fields.
        """
        cmd = [tshark, '-r', self.pcap_file] + options
        if display_filter:
            cmd.extend(['-Y', display_filter])
        if custom_fields:
            fields_options = ['-e' + field.strip() for field in custom_fields.split(',')]
            cmd.extend(['-T', 'fields'] + fields_options)
        completed_process: subprocess.CompletedProcess = subprocess.run(cmd, stdout=subprocess.PIPE,
                                                                        stderr=subprocess.PIPE, shell=False, check=False)
        return completed_process.stdout.decode()

    def _process_protocol(self, display_filter: str, fields: List[str]) -> str:
        """
        Constructs and executes a tshark command to extract specific fields from packets
        that match a given display filter.
        """
        options = ['-T', 'fields'] + ['-e' + field for field in fields]
        output = self._run_tshark_command(options, display_filter=display_filter)
        return output

    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ T྇S྇h྇a྇r྇k྇ C྇o྇m྇m྇a྇n྇d྇ M྇e྇t྇h྇o྇d྇s྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ A༙྇u༙྇t༙྇o༙྇n༙྇o༙྇m༙྇o༙྇u༙྇s༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def process_and_display_verbose_results(self) -> None:
        """
        Processes and displays verbose results from a TShark analysis.

        This method attempts to read verbose results and fields and displays them.
        If the unpacking of results encounters a ValueError, it catches the error
        and prints an error message. If verbose results or fields are None, or if
        the result from read_verbose is not a tuple or list, it displays a message
        indicating missing or invalid data.
        """
        try:
            # Attempt to read the verbose results and fields
            result = self.read_verbose()

            # Check if the result is a tuple or list with two elements
            if isinstance(result, (tuple, list)) and len(result) == 2:
                verbose_results, verbose_fields = result
                # Check if verbose_results and verbose_fields are not None before using them
                if verbose_results is not None and verbose_fields is not None:
                    self.display_results(verbose_results, verbose_fields)
                else:
                    # Display message if data is missing
                    print("Unable to display results due to missing data.")
            else:
                print("Invalid or unexpected data format from read_verbose.")

        except ValueError as e:
            # Catch and handle the ValueError, displaying the error message
            print(f"Caught an error: {e}")

    def process_and_display_user_agents(self) -> None:
        """
        Processes and displays user agent results from a TShark analysis.

        This method attempts to read user agent results and fields and displays them.
        If the unpacking of results encounters a ValueError, it catches the error
        and prints an error message. If user agent results or fields are None, or if
        the result from user_agent is not a tuple or list, it displays a message
        indicating missing or invalid data.
        """
        try:
            # Attempt to read the user agent results and fields
            result = self.user_agent()

            # Check if the result is a tuple or list with two elements
            if isinstance(result, (tuple, list)) and len(result) == 2:
                user_agent_results, user_agent_fields = result
                # Check if user_agent_results and user_agent_fields are not None before using them
                if user_agent_results is not None and user_agent_fields is not None:
                    self.display_results(user_agent_results, user_agent_fields)
                else:
                    # Display message if data is missing
                    print("Unable to display results due to missing data.")
            else:
                print("Invalid or unexpected data format from user_agent.")

        except ValueError as e:
            # Catch and handle the ValueError, displaying the error message
            print(f"Caught an error: {e}")

    def host_enum(self) -> Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]:
        """
        Enumerates hosts for different protocols by running tshark commands.
        Returns:
            Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]: A tuple containing the results and the
                                                                    fields used for each protocol.
        """
        protocols = {
            'dhcp': ['dhcp', 'dhcp.option.hostname'],
            'nbns': ['nbns', 'nbns.name'],
            'kerberos': ['kerberos.CNameString and (kerberos.CNameString contains "$")', 'kerberos.CNameString'],
            'smb': ['smb', 'ntlmssp.auth.hostname'],
            'browser': ['browser', 'browser.server'],
            'dcerpc': ['dcerpc', 'netlogon.secchan.nl_auth_message.nb_host'],
            'llmnr': ['llmnr', 'dns.qry.name'],
            'cldap': ['cldap', 'ldap.assertionValue']
        }
        results = {}
        fields = {}
        for protocol, params in protocols.items():
            filter, field = params
            output = self._run_tshark_command(['-Y', filter, '-T', 'fields', '-e', field])
            results[protocol] = self._process_output(output)
            fields[protocol] = field
        return results, fields

    def user_enum(self) -> Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]:
        """
        Enumerates users for different protocols by running tshark commands.
        Returns:
            Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]: A tuple containing the results and the
                                                                    fields used for each protocol.
        """
        protocols = {
            'samr': ['samr', 'samr.samr_LookupNames.names'],
            'ldap': ['ldap contains "CN=Users"', 'ldap.baseObject'],
            'kerberos': ['kerberos.CNameString and !(kerberos.CNameString contains "$")', 'kerberos.CNameString'],
            'smb': ['smb', 'ntlmssp.auth.username']
        }
        results = {}
        fields = {}
        for protocol, params in protocols.items():
            filter, field = params
            output = self._run_tshark_command(['-Y', filter, '-T', 'fields', '-e', field])
            results[protocol] = self._process_output(output)
            fields[protocol] = field
        return results, fields

    def pcap_info(self) -> str:
        """
        Retrieves information about the pcap file using capinfo.
        """
        return self._run_command([capinfo, self.pcap_file])

    def iophs(self) -> str:
        """
        Generates Input/Output Protocol Hierarchy Statistics from the pcap file.
        """
        return self._run_tshark_command(['-qz', 'io,phs'])

    def expert_chat(self) -> str:
        """
        Runs TShark to obtain 'expert chat' diagnostic messages from the pcap file.
        """
        return self._run_tshark_command(['-qz', 'expert,chat'])

    def failed_connections(self) -> str:
        """
        Identifies and returns information about failed TCP connection attempts.
        """
        return self._run_tshark_command(['-Y', 'tcp.analysis.retransmission and tcp.flags eq 0x0002'])

    def whois_ip(self) -> None:
        """
        Retrieves WHOIS information for unique destination IP addresses found in the pcap file.
        """
        # Use tshark to extract destination IP addresses from the pcap file
        check_tshark_output = self._run_tshark_command(['-T', 'fields', '-e', 'ip.dst'])
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

    def arp_thunt(self) -> Tuple[str, str]:
        """
        Searches for ARP poisoning attacks within the pcap file.
        """
        return self._run_tshark_command(['-Y', 'arp.duplicate-address-detected', '-T', 'fields', '-e',
                                         'arp.duplicate-address-detected']), \
            self._run_tshark_command(['-Y', 'arp.packet-storm-detected', '-T', 'fields', '-e',
                                      'arp.packet-storm-detected'])

    def user_agent(self) -> Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]:
        """
        Extracts and counts occurrences of HTTP user agents from network traffic data.

        This method executes a TShark command to capture the 'http.user_agent' fields from the pcap file.
        It then processes this output to count the occurrences of each unique user agent, providing insights
        into the different types of clients that have interacted with the network.

        Returns:
            Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]: A tuple containing two dictionaries.
            The first dictionary maps a descriptive key to a list of tuples, where each tuple contains a user
            agent string and its count. The second dictionary provides a mapping for field descriptions used in
            the output.
        """
        cmd = ['-T', 'fields', '-e', 'http.user_agent']
        output = self._run_tshark_command(cmd)
        user_agents = [ua for ua in output.strip().split('\n') if ua.strip()]
        user_agent_counts = Counter(user_agents).most_common()
        formatted_results = {"HTTP User Agents": list(user_agent_counts)}
        fields_dict = {"HTTP User Agents": "User Agent"}
        return formatted_results, fields_dict

    def web_basic(self) -> str:
        """
        Extracts basic web traffic information from the pcap file.
        """
        print('')
        print(f"{Color.GREEN}Web Traffic:{Color.END}")
        print('')
        return self._run_tshark_command(['-Y', '(http.request or http.response or tls.handshake.type eq 1) and !(ssdp)'])

    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ A྇u྇t྇o྇n྇o྇m྇o྇u྇s྇ M྇e྇t྇h྇o྇d྇s྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ U༙྇s༙྇e༙྇r༙྇ I༙྇n༙྇p༙྇u༙྇t༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def find_beacons(self, ip_address: Optional[str] = None, interval_frequency: Optional[str] = None) -> None:
        """
        Identifies beacon-like traffic patterns for a specified IP address and interval frequency,
        and plots the data using a line graph. It prompts the user for input if the IP address or interval frequency is not provided.

        Parameters:
        ip_address (Optional[str]): The IPv4 address to analyze for beacon-like patterns. If None, the user is prompted to enter an IP address.
        interval_frequency (Optional[str]): The frequency, in seconds, at which to analyze the traffic patterns. If None, the user is prompted to enter an interval frequency.

        Returns:
        None: This method does not return anything. It displays a line graph showing the traffic patterns.
        """
        if ip_address is None:
            ip_address = input("Enter the IPv4 address you wish to look for patterns to determine beacons: ")

            while not is_valid_ipv4_address(ip_address):
                ip_address = input("Invalid IP. Please enter a valid IPv4 address: ")

        if interval_frequency is None:
            interval_frequency = input("Enter the interval frequency (in seconds): ")

            while not is_valid_interval(interval_frequency):
                interval_frequency = input("Invalid interval. Please enter a valid interval frequency in seconds: ")

        # Run TShark command and capture output
        tshark_output = self._run_tshark_command(
            ['-qz',
             f'io,stat,{interval_frequency},MAX(frame.time_relative)frame.time_relative,ip.addr=={ip_address},MIN(frame.time_relative)frame.time_relative']
        )

        print("TShark Output:", tshark_output)

        # Process TShark output to extract data for plotting
        times, frames, bytes_data = self._process_tshark_output(tshark_output)

        # Calculate total duration based on the time intervals
        total_duration = times[-1] - times[0] if times else 0

        # Create figure and axis objects
        fig, ax1 = plt.subplots(figsize=(12, 8))

        # Plotting frames
        frame_line, = ax1.plot(times, frames, marker='o', color='blue', label='Frame Count')

        # Set x-axis label
        ax1.set_xlabel(f"Time Intervals (s) - Total Duration: {total_duration} s", labelpad=15)

        # Add additional text below the x-axis label for the chosen interval frequency
        ax1.text(0.5, -0.15, f"Interval Frequency: {interval_frequency} s",
                 transform=ax1.transAxes, ha='center', va='center', fontsize=10)

        # Plotting bytes on a secondary y-axis
        ax2 = ax1.twinx()
        bytes_line, = ax2.plot(times, bytes_data, marker='x', color='red', label='Byte Count')

        # Setting title
        plt.title(f"Network Traffic Patterns for IP {ip_address}")

        # Creating combined legend for both lines
        lines = [frame_line, bytes_line]
        labels = [line.get_label() for line in lines]
        ax1.legend(lines, labels, loc='upper left')

        # Explicitly adjust subplots to fit the figure area
        fig.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.17)

        # Show grid and plot
        ax1.grid(True)
        plt.show()

    # @staticmethod
    def _process_tshark_output(self, output: str):
        """
        Processes the output from the TShark command to extract time intervals, frame counts, and byte counts.

        The function assumes the output is formatted in a table where each row represents a time interval
        and the columns include the maximum and minimum frame times, the number of frames, and the number
        of bytes.

        Parameters:
        output (str): The raw string output from the TShark command.

        Returns:
        tuple: A tuple containing three lists:
            times (list of float): A list of interval start times extracted from the output.
            frames (list of int): A list of frame counts corresponding to each time interval.
            bytes_data (list of int): A list of byte counts corresponding to each time interval.
        """
        times = []  # List to store interval start times
        frames = []  # List to store frame counts
        bytes_data = []  # List to store byte counts

        # Split the output into lines
        lines = output.strip().split('\n')

        # Flag to start reading the table data
        start_reading = False

        for line in lines:
            # Start reading after the table header is detected
            if line.startswith('| Interval'):
                start_reading = True
                continue

            if start_reading and line.startswith('|'):
                # Extract data from each line
                # Line format: "|   0 <> 10  | 9.178748 | 0 | 0 | 0.000000 |"
                parts = line.split('|')
                if len(parts) >= 6:
                    try:
                        interval = parts[1].strip()  # "0 <> 10"
                        frame_count = parts[3].strip()  # "0"
                        byte_count = parts[4].strip()  # "0"

                        # Extract the start of the interval
                        interval_start = interval.split('<>')[0].strip()
                        times.append(float(interval_start))

                        # Convert frame and byte counts to integers
                        frames.append(int(frame_count))
                        bytes_data.append(int(byte_count))
                    except ValueError:
                        # Skip lines that can't be parsed
                        continue

        return times, frames, bytes_data

    def display_filter(self) -> str:
        """
        Applies a custom display filter specified by the user and returns the filtered output.
        """
        get_input = input("Enter a valid display filter: ")
        view_verbose = input("Expand the packet layers? (Y/N): ")
        view_all_pkts = input("View all packets? (Y/N): ")
        custom_fields = input("Specify custom fields? (Y/N): ")

        options = ['-Y', get_input]

        if view_verbose.lower() == "y":
            options.append('-V')
        if view_all_pkts.lower() == "n":
            how_many_pkts = input("How many packets do you want to see? ")
            options.extend(['-c', how_many_pkts])
        elif view_all_pkts.lower() == "y":
            pass

        # Call _run_tshark_command with or without custom fields
        if custom_fields.lower() == "y":
            custom_field_options = input("Enter one or more custom field options (comma-separated): ")
            output = self._run_tshark_command(options, custom_fields=custom_field_options)
            # Process the output if custom fields were specified
            non_blank_lines = [line for line in output.splitlines() if line.strip()]
            sorted_output = sorted(non_blank_lines, key=lambda x: x.split()[0])
            counts = Counter(sorted_output)
            sorted_by_count_output = '\n'.join(f'{count} {line}' for line, count in counts.most_common())
            return sorted_by_count_output
        else:
            output = self._run_tshark_command(options)
            return output

    def dns_hunt(self) -> None:
        """
        Searches for DNS queries or responses involving a specific domain.
        """

        while True:

            try:
                ask_dns = input('Enter the domain you want to search for, enclosed in double quotes (".onion", "wtfismyip.com"):\nOr type `exit` to quit: ')
                if ask_dns.lower() == 'exit':
                    break

                result = self._run_tshark_command(['-Y', 'dns matches ' + ask_dns])

                print(result)

            except subprocess.SubprocessError as e:
                print(f"A subprocess error occurred: {e}")

            except Exception as e:
                print(f"An unexpected error occurred: {e}")

            print("\n")

    def viewframe_getstream(self) -> str:
        """
        Retrieves the TCP stream index for a specified frame number.
        """
        ask_frame = input("Enter the frame number you'd like to get the tcp stream index for: ")
        return self._run_tshark_command(['-Y', f"frame.number == {ask_frame}", '-T', 'fields', '-e', 'tcp.stream'])

    def tcp_stream(self) -> str:
        """
        Follows a specified TCP stream and returns its contents.
        """
        get_tcp_stream_number = input_prompt("Which TCP stream index would you like to see? ", is_valid_digit)
        return self._run_tshark_command(['-qz', f'follow,tcp,ascii,{get_tcp_stream_number}'])

    def http_stream(self) -> str:
        """
        Follows a specified HTTP stream and returns its contents.
        """
        get_http_stream_number = input_prompt("Which HTTP stream index would you like to see? ", is_valid_digit)
        return self._run_tshark_command(['-qz', f'follow,http,ascii,{get_http_stream_number}'])

    def show_packets(self) -> None:
        """
        Continuously prompts the user to display network packets.

        This method allows the user to choose between displaying all packets or packets
        of a specific protocol. The user can repeatedly make this choice, or choose to exit
        the loop. If a specific protocol is chosen, only packets related to that protocol are displayed.
        The method handles subprocess errors and unexpected exceptions during its execution.
        """

        while True:

            try:
                get_proto = input("Show all packets? (yes or no, or 'exit' to quit) ")
                print('')

                if get_proto.lower() == 'exit':
                    break

                # If the user doesn't want to show all packets
                if get_proto.lower() == "no":
                    which_proto = input("Which protocol would you like to see all packets for? ")
                    print('')
                    # Extract packets for the specified protocol
                    print('All ' + which_proto + ' packets:\n\n' + self._run_tshark_command(['-Y', which_proto]))

                # If the user wants to show all packets
                elif get_proto.lower() == "yes":
                    print('All packets:\n\n' + self._run_tshark_command([]))

                else:
                    print("Invalid input. Please enter 'yes' or 'no'.")

            except subprocess.SubprocessError as e:
                print(f"A subprocess error occurred: {e}")

            except Exception as e:
                print(f"An unexpected error occurred: {e}")

            print("\n")

    def statistics(self) -> None:
        """
        Continuously prompts the user to choose a type of network statistics to view, until they choose to exit.
        Supported statistics include conversations, server response times, tree statistics, and host listings.
        """

        while True:

            which_stats = input(
                f"{Color.LIGHTYELLOW}What type of statistics do you want to view (conv/hosts/srt/tree)?\nEnter your choice or 'exit' to quit:  {Color.END}: ")
            if which_stats.lower() == 'exit':
                break

            try:

                def conversations() -> None:
                    ask_protocol = input(
                        f"{Color.CYAN}Which protocol would you like to view conversations for? "
                        f"(bluetooth/eth/ip/tcp/usb/wlan){Color.END}: ")
                    # Dictionary mapping protocol names to TShark commands
                    protocol_commands: Dict[str, List[str]] = {
                        'bluetooth': ['conv,bluetooth'],
                        'eth': ['conv,eth'],
                        'ip': ['conv,ip'],
                        'tcp': ['conv,tcp'],
                        'usb': ['conv,usb'],
                        'wlan': ['conv,wlan']
                    }
                    if ask_protocol in protocol_commands:
                        tshark_command = ['-qz'] + protocol_commands[ask_protocol]
                        print(self._run_tshark_command(tshark_command))
                    else:
                        print("Unsupported protocol")

                def _server_resp_times() -> None:
                    ask_protocol = input(
                        f"{Color.GOLD}Which protocol would you like to see server response times for? "
                        f"(icmp/ldap/smb/smb2/srvsvc/drsuapi/lsarpc/netlogon/samr){Color.END}: ")
                    protocol_commands: Dict[str, List[str]] = {
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
                        tshark_command = ['-qz'] + protocol_commands[ask_protocol]
                        print(self._run_tshark_command(tshark_command))
                    else:
                        print("Unsupported protocol")

                def tree() -> None:
                    ask_protocol = input(
                        f"{Color.LIGHTGREEN}Which protocol would you like to see tree statistics for? "
                        f"(dns/ip_hosts/http/http_req/http_srv/plen/ptype){Color.END}: ")
                    protocol_commands: Dict[str, List[str]] = {
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
                        tshark_command = ['-qz'] + protocol_commands[ask_protocol]
                        print(self._run_tshark_command(tshark_command))
                    else:
                        print("Unsupported protocol")

                def hosts() -> None:
                    tshark_command = ['-qz', 'hosts,ip']
                    print(self._run_tshark_command(tshark_command))

                # Mapping of statistics types to the corresponding function calls
                stats_functions: Dict[str, Any] = {
                    'conv': conversations,
                    'srt': _server_resp_times,
                    'tree': tree,
                    'hosts': hosts
                }

                func = stats_functions.get(which_stats)

                if func:
                    func()
                else:
                    print("Unsupported protocol")

            except subprocess.SubprocessError as e:
                print(f"A subprocess error occurred: {e}")

            except Exception as e:
                print(f"An unexpected error occurred: {e}")

            print("\n")

    def read_verbose(self) -> Union[Tuple[Dict[Any, List[Tuple[Any, int]]], Dict[Any, Any]], str]:
        """
        Reads and processes verbose information based on a user-specified protocol in a TShark analysis.

        This method prompts the user to select a protocol and processes the TShark output based on this protocol.
        It returns a tuple of processed output and field dictionary if successful, or an error message string if
        an exception occurs.

        Returns:
            Union[Tuple[Dict, Dict], str]: A tuple containing processed verbose results and fields if successful,
                                           or an error message string in case of an exception.
        """
        try:
            # Prompt the user to select a protocol to search within the pcap file.
            ask_protocol = input(f"{Color.CYAN}Choose a protocol to search (dns, eth, http, icmp, smb2, tls){Color.END}: ")

            # Dictionary mapping protocol names to their corresponding field names and display filters.
            protocol_args = {
                'eth': (['eth.addr.oui_resolved'], 'eth'),          # Ethernet protocol, filter on OUI addresses
                'smb2': (['smb2.filename'], 'smb2.filename'),       # SMB2 protocol, filter on filenames
                'dns': (['dns.qry.name'], 'dns'),                   # DNS protocol, filter on query names
                'tls': (['tls.handshake.extensions_server_name'], 'tls'),  # TLS protocol, filter on server name
                'http': (['http.request.full_uri'], 'http'),        # HTTP protocol, filter on requests

            }
            if ask_protocol in protocol_args:
                fields, display_filter = protocol_args[ask_protocol]
                output = self._process_protocol(display_filter, fields)
                processed_output = self.process_output(output, ask_protocol)
                fields_dict = {ask_protocol: "Description"}
                return processed_output, fields_dict

            else:
                raise ValueError(f"Unknown protocol: {ask_protocol}")

        except ValueError as err:
            # Handle the error
            logging.error(err)
            # print(f"An error occurred: {err}. Please enter a valid protocol.")
            return f"An error occurred: {err}. Please enter a valid protocol."

    
    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ U྇s྇e྇r྇ I྇n྇p྇u྇t྇ M྇e྇t྇h྇o྇d྇s྇


if __name__ == "__main__":
    pass
