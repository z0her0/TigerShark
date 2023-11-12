# Standard library imports
import json  # JSON encoder and decoder
import logging
import os  # Operating system interfaces
import subprocess  # Process creation and management
from collections import Counter  # Container for counting hashable objects
# Type hinting imports
from typing import Optional, Dict, List, Tuple, Union, Any

from dcerpc_method_abuse_notes import get_dcerpc_info  # MSRPC to ATT&CK lookup table
# Custom module imports
from make_colorful import Color  # Terminal color output utility
from make_helpers import (
    input_prompt,  # Standardized user input prompt
    is_valid_interval,  # Interval validation
    is_valid_digit,  # Digit validation
    is_valid_ipv4_address,  # IPv4 address validation
    set_tshark_path,  # Set the path to the tshark application
    get_input_opnum,  # Get and validate user input
    process_output,  # Takes input, processes it, cleans it, and returns it
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


    # »»————--༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇ B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ S༙྇t༙྇a༙྇t༙྇i༙྇c༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇ -༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇————-««


    @staticmethod
    def _run_command(cmd: List[str]) -> str:
        """
        Runs a command in a subprocess and returns its output.
        """
        completed_process: subprocess.CompletedProcess = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)
        return completed_process.stdout.decode()

    @staticmethod
    def display_results(results: Dict[str, List[Tuple[str, int]]], fields: Dict[str, str]) -> None:
        """
        Displays the results of the tshark command processing in a formatted manner.
        Args:
            results (Dict[str, List[Tuple[str, int]]]): The processed results from tshark commands.
            fields (Dict[str, str]): The fields used for each protocol in the tshark command.
        """
        for protocol, data in results.items():
            field = fields[protocol]
            print(f"\n")
            print(f"{Color.MAROON}{'Count'.rjust(6)}  Host   {protocol}:{field}{Color.END}")
            print('-' * 40)
            for host, count in data:
                print(f"{str(count).rjust(6)}  {host}")

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
        # Remove blank lines and sort
        sorted_output = [line for line in output.strip().split('\n') if line.strip()]
        # Count and sort based on counts
        return Counter(sorted_output).most_common()

    @staticmethod
    def get_dcerpc_abuse_info() -> None:
        """
        Retrieves and prints abuse information for a specified DCERPC service and method.
        """
        service_name_input = input("Enter the service (e.g., samr, drsuapi, netlogon, lsarpc, srvsvc): ")
        opnum_input = get_input_opnum()
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


    # »»————--྇-྇-྇-྇-྇-྇-྇-྇ E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇  :྇ S྇t྇a྇t྇i྇c྇ M྇e྇t྇h྇o྇d྇s྇ -྇-྇-྇-྇-྇-྇-྇————-««


    # »»————--༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇ B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ T༙྇S༙྇h༙྇a༙྇r༙྇k༙྇ C༙྇o༙྇m༙྇m༙྇a༙྇n༙྇d༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇ -༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇————-««


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
                                                                        stderr=subprocess.PIPE, check=False)
        return completed_process.stdout.decode()

    def _process_protocol(self, display_filter: str, fields: List[str]) -> str:
        """
        Constructs and executes a tshark command to extract specific fields from packets
        that match a given display filter.
        """
        # Construct the tshark command options for extracting fields
        options = ['-T', 'fields'] + ['-e' + field for field in fields]
        # Run the tshark command and capture the output
        output = self._run_tshark_command(options, display_filter=display_filter)
        return output


    # »»————--྇-྇-྇-྇-྇-྇-྇-྇ E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇  :྇ T྇S྇h྇a྇r྇k྇ C྇o྇m྇m྇a྇n྇d྇ M྇e྇t྇h྇o྇d྇s྇ -྇-྇-྇-྇-྇-྇-྇————-««


    # »»————--༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇ B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ A༙྇u༙྇t༙྇o༙྇n༙྇o༙྇m༙྇o༙྇u༙྇s༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇ -༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇————-««


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

    def user_agent(self) -> str:
        """
        Analyzes and returns a count of user agents found in the HTTP traffic.
        """
        # Extract User Agent strings using tshark
        cmd = ['-T', 'fields', '-e', 'http.user_agent']
        output = self._run_tshark_command(cmd)
        # Clean, split, and filter out blank User Agent strings
        user_agents = [ua for ua in output.strip().split('\n') if ua.strip()]
        user_agent_counts = Counter(user_agents).most_common()
        return json.dumps(user_agent_counts, indent=2)

    def web_basic(self) -> str:
        """
        Extracts basic web traffic information from the pcap file.
        """
        print('')
        print(f"{Color.GREEN}Web Traffic:{Color.END}")
        print('')
        return self._run_tshark_command(['-Y', '(http.request or http.response or tls.handshake.type eq 1) and !(ssdp)'])

    # »»————--྇-྇-྇-྇-྇-྇-྇-྇ E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇  :྇ A྇u྇t྇o྇n྇o྇m྇o྇u྇s྇ M྇e྇t྇h྇o྇d྇s྇ -྇-྇-྇-྇-྇-྇-྇————-««


    # »»————--༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇ B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ U༙྇s༙྇e༙྇r༙྇ I༙྇n༙྇p༙྇u༙྇t༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇ -༙྇-༙྇-༙྇-༙྇-༙྇-༙྇-༙྇————-««


    def find_beacons(self, ip_address: Optional[str] = None, interval_frequency: Optional[str] = None) -> Any:
        """
        Identifies beacon-like traffic patterns for a specified IP address and interval frequency.
        """
        if ip_address is None:
            ip_address = input_prompt(
                "Enter the IPv4 address you wish to look for patterns to determine beacons (Example valid input: "
                "10.10.14.19): ", is_valid_ipv4_address)
        if interval_frequency is None:
            interval_frequency = input_prompt(
                "Enter the interval frequency (Example: for 120 secs intervals, enter 120): ",
                is_valid_interval)
        return self._run_tshark_command(['-qz',
                                         f'io,stat,{interval_frequency},MAX(frame.time_relative)frame.time_relative,ip.addr=={ip_address},MIN(frame.time_relative)frame.time_relative'])

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
            # If there is a need to add additional options when viewing all packets
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

    def dns_hunt(self) -> str:
        """
        Searches for DNS queries or responses involving a specific domain.
        """
        ask_dns = input("Enter the domain you want to search for here in double quotes: ")
        return self._run_tshark_command(['-Y', 'dns matches ' + f"{ask_dns}"])

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

    def show_packets(self) -> str:
        """
        Displays packets based on the user's choice of either all packets or a specific protocol.
        """
        get_proto = input("Show all packets? (yes or no) ")
        print('')
        # If the user doesn't want to show all packets
        if get_proto == "no":
            which_proto = input("Which protocol would you like to see all packets for? ")
            print('')
            # Extract packets for the specified protocol
            return 'All ' + which_proto + ' packets:\n\n' + self._run_tshark_command(['-Y', which_proto])

        # If the user wants to show all packets
        elif get_proto == "yes":
            return 'All packets:' + self._run_tshark_command([])

    def statistics(self) -> Optional[str]:
        """
        Displays various types of statistics like conversations, server response times, or tree statistics
        based on the user's choice.
        """
        which_stats = input(
            f"{Color.LIGHTYELLOW}What type of statistics do you want to view? (conv/hosts/srt/tree): {Color.END}: ")

        def conversations() -> None:
            """
            Asks the user for a specific protocol and prints the conversation statistics
            for that protocol using TShark. It accesses a predefined dictionary of commands
            to generate the appropriate statistics.
            """
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

        def server_resp_times() -> None:
            """
            Asks the user for a specific protocol and prints the server response time
            statistics for that protocol using TShark. It accesses a predefined dictionary
            of commands to generate the appropriate statistics.
            """
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
            """
            Asks the user for a specific protocol and prints the protocol tree statistics
            for that protocol using TShark. It accesses a predefined dictionary of commands
            to generate the appropriate statistics.
            """
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
            """
            Prints the host statistics from the PCAP file using TShark.
            """
            tshark_command = ['-qz', 'hosts,ip']
            print(self._run_tshark_command(tshark_command))

        # Mapping of statistics types to the corresponding function calls
        stats_functions: Dict[str, Any] = {
            'conv': conversations,
            'srt': server_resp_times,
            'tree': tree,
            'hosts': hosts
        }

        # Call the selected function or print an error if the choice is invalid
        return stats_functions.get(which_stats, lambda: "Unsupported protocol")()

    def read_verbose(self) -> Union[List[Tuple[str, int]], Any]:
        """
        Provides verbose information based on the user's choice of protocol to search within the pcap file.
        """
        try:
            # Prompt the user to select a protocol to search within the pcap file.
            ask_protocol = input(f"{Color.CYAN}Choose a protocol to search{Color.END}: ")

            # Dictionary mapping protocol names to their corresponding field names and display filters.
            # This is used to construct the appropriate tshark command for each protocol.
            protocol_args = {
                'eth': (['eth.addr.oui_resolved'], 'eth'),          # Ethernet protocol, filter on OUI addresses
                'smb2': (['smb2.filename'], 'smb2.filename'),       # SMB2 protocol, filter on filenames
                'dns': (['dns.qry.name'], 'dns'),                   # DNS protocol, filter on query names
                'tls': (['tls.handshake.extensions_server_name'], 'tls'),  # TLS protocol, filter on server name
                'http': (['http.request.full_uri'], 'http'),        # HTTP protocol, filter on requests

            }

            # Common tshark command processing
            if ask_protocol in protocol_args:
                fields, display_filter = protocol_args[ask_protocol]
                output = self._process_protocol(display_filter, fields)
                processed_output = process_output(output, ask_protocol)
                return json.dumps(processed_output, indent=2)

            # 'icmp' Protocol
            elif ask_protocol == "icmp":
                # Common tshark arguments shared by all commands
                tshark_args = ['-t', 'ad']

                # Capture ICMP Echo Requests data, and Echo Replies data
                icmp_req = self._run_tshark_command([*tshark_args, '-Y', '(icmp.type == 8) && (icmp.code == 0)'])
                icmp_resp = self._run_tshark_command([*tshark_args, '-Y', '(icmp[0] == 0) && (icmp[1] == 0)'])

                # Return formatted ICMP data
                return (f"{Color.LIGHTBLUE}ECHO Requests (frame #, time, src ip, dst ip, info):{Color.END}\n{icmp_req}\n"
                        f"{Color.LIGHTGREEN}ECHO replies (frame #, time, src ip, dst ip, info):{Color.END}\n{icmp_resp}")

            else:
                raise ValueError(f"Unknown protocol: {ask_protocol}")

        except ValueError as err:
            # Handle the error
            logging.error(err)
            print(f"An error occurred: {err}. Please enter a valid protocol.")


    # »»————--྇-྇-྇-྇-྇-྇-྇-྇ E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇  :྇ U྇s྇e྇r྇ I྇n྇p྇u྇t྇ M྇e྇t྇h྇o྇d྇s྇ -྇-྇-྇-྇-྇-྇-྇————-««


if __name__ == '__main__':
    pass
