"""
A custom TShark class is at the core of this module and acts as a wrapper around TShark command-line
utilities. The class includes methods for extracting specific data from pcap files, such as WHOIS information, 
user agents, and a couple dozen more different types of information.
"""
import ipaddress
import logging
import sys
import os
import subprocess
import requests
from collections import Counter
from typing import Optional, Dict, List, Tuple, Any, Union
from logging.handlers import RotatingFileHandler
import warnings
from urllib3.exceptions import InsecureRequestWarning

from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from rich.table import Table
from rich.console import Console
import dns.resolver

from make_colorful import Color, ColorRandomRGB
from dcerpc_data import dcerpc_services
from dcerpc_method_abuse_notes import (
    get_dcerpc_info,
    list_methods,
    enhanced_search)
from make_helpers import (
    input_prompt,
    is_valid_interval,
    is_valid_digit,
    is_valid_ipv4_address,
    set_tshark_path,
    get_input_opnum,
)


warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# tuple unpacking into the variables tshark and capinfo
tshark, capinfo = set_tshark_path()


class ColorfulFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels."""
    COLOR_CODES = {
        logging.DEBUG: Color.BLUE,
        logging.INFO: Color.GREEN,
        logging.WARNING: Color.YELLOW,
        logging.ERROR: Color.RED,
        logging.CRITICAL: Color.MAROON
    }
    RESET_CODE = Color.END

    def format(self, record):
        """
        Apply color codes to log messages based on their severity level.
        """
        color_code = self.COLOR_CODES.get(record.levelno)
        message = super().format(record)
        return f"{color_code}{message}{self.RESET_CODE}" if color_code else message


class TShark:
    """
    A class to provide an interface to the TShark network protocol analyzer.
    """

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ Initialization༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    @staticmethod
    def get_logger(log_file: str = 'tshark.log', level: str = 'INFO', log_format: str = None,
                   max_log_size: int = 10 * 1024 * 1024, backup_count: int = 5, suppress_output: bool = False):
        """
        Static method to initialize and return a logger object.
        """
        logger = logging.getLogger('TSharkLogger')

        # Set log level
        numeric_level = getattr(logging, level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f'Invalid log level: {level}')

        logger.setLevel(numeric_level)
        
        # Avoid adding handlers if they are already set up
        if logger.hasHandlers():
            logger.handlers.clear()
        
        # Log format
        if not log_format:
            log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        formatter = logging.Formatter(log_format)

        try:
            # Console handler
            if not suppress_output:
                c_handler = logging.StreamHandler(sys.stdout)
                c_handler.setFormatter(ColorfulFormatter(log_format or '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
                logger.addHandler(c_handler)
            
            # File handler with rotation
            if log_file:
                # Extract directory from log_file path
                log_dir = os.path.dirname(log_file)
                
                # Check if the directory path is not empty
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)

                f_handler = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count)
                f_handler.setFormatter(formatter)
                logger.addHandler(f_handler)

        except Exception as e:
            print(f"Error setting up logger: {e}", file=sys.stderr)

        return logger

    def __init__(self, pcap_file: str) -> None:
        """
        Initializes the TShark class with the specified pcap file.
        """
        self.logger = self.get_logger(log_file='tshark.log', level='INFO')
        self.pcap_file: str = pcap_file
        self.logger.info(f"TShark initialized with pcap file: {self.pcap_file}")
        self.proc: Optional[subprocess.CompletedProcess] = None

        if not os.path.isfile(tshark):
            self.logger.error(f'TShark not found at specified path: {tshark}')
            print("\n")
            raise FileNotFoundError('Cannot find tshark in ' + tshark)

    # END༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ Initialization M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ Utility M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def run_command(self, cmd: List[str]) -> str:
        """
        Runs a command in a subprocess and returns its output.
        """
        try:
            completed_process: subprocess.CompletedProcess = subprocess.run(cmd, stdout=subprocess.PIPE, shell=False,
                                                                            check=False)
            self.logger.debug(f"Command executed: {' '.join(cmd)}")
            return completed_process.stdout.decode()

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command execution failed: {e}", exc_info=True)

    @staticmethod
    def profile_exists(profile_name: str) -> bool:
        """
        This method checks for the existence of a directory corresponding to the given profile name
        in the user's personal Wireshark profiles path.
        """
        wireshark_profiles_path = os.path.expanduser('~/.config/wireshark/profiles')
        profile_path = os.path.join(wireshark_profiles_path, profile_name)
        return os.path.isdir(profile_path)

    def _run_tshark_command(self, options: List[str], display_filter: Optional[str] = None,
                            custom_fields: Optional[str] = None, profile_name: Optional[str] = 'THunt') -> str:
        """
        Execute a tshark command with the specified options, display filter, custom fields, and profile.

        This method constructs and executes a tshark command based on the provided arguments. If the specified
        profile does not exist, it falls back to the default profile and logs a warning.
        """
        try:
            cmd = [tshark, '-r', self.pcap_file] + options
            if profile_name:
                if self.profile_exists(profile_name):
                    cmd.extend(['-C', profile_name])
                else:
                    self.logger.warning(f"Profile {profile_name} does not exist. Using default profile.")
            if display_filter:
                cmd.extend(['-Y', display_filter])
            if custom_fields:
                fields_options = ['-e' + field.strip() for field in custom_fields.split(',')]
                cmd.extend(['-T', 'fields'] + fields_options)

            self.logger.debug(f"Running tshark command: {' '.join(cmd)}")
            completed_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                                               check=False)
            if completed_process.returncode != 0:
                self.logger.error(f"TShark command execution failed with error: {completed_process.stderr.decode()}")
                return ""

            return completed_process.stdout.decode()

        except subprocess.CalledProcessError as e:
            self.logger.error(f"TShark command execution failed: {e}", exc_info=True)
            return ""

    def _process_protocol(self, display_filter: str, fields: List[str]) -> str:
        """
        Constructs and executes a TShark command to extract specific fields from packets
        that match a given display filter.
        """
        options = ['-T', 'fields'] + ['-e' + field for field in fields]
        output = self._run_tshark_command(options, display_filter=display_filter)
        return output

    @staticmethod
    def process_output_host_user_enum(output: str) -> List[Tuple[str, int]]:
        """Returns a list of tuples, where each tuple contains a line (or element) and its count."""
        sorted_output = [line for line in output.strip().split('\n') if line.strip()]
        return Counter(sorted_output).most_common()

    @staticmethod
    def process_output_read_verbose(output, protocol):
        """Returns a dictionary with a single key-value pair. The key is protocol, and the value is a list of tuples"""
        lines = output.strip().split('\n')
        cleaned_lines = [line.strip().replace('\t', '') for line in lines if line.strip()]
        sorted_counts = Counter(cleaned_lines).most_common()
        return {protocol: sorted_counts}

    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ Utility྇ M྇e྇t྇h྇o྇d྇s྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ Data Extraction༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def spambot(self) -> str:
        """
        Executes a tshark command to check for TLS handshake attempts on email ports which can be indicative of
        spamming activity.

        The method constructs and executes a tshark command that filters for TLS handshakes (`tls.handshake.type eq 1`)
        on common email ports (25, 465, 587) used for sending emails. This can help identify potential spambot activity
        as these handshakes are indicative of email sending attempts.
        """
        try:
            self.logger.info("Running spambot method.")
            spambot_info = self._run_tshark_command(['-Y', 'tls.handshake.type eq 1 and (tcp.port eq 25 or tcp.port eq 465 or tcp.port eq 587)'])

            return spambot_info

        except Exception as e:
            self.logger.error(f"Error in spambot method: {e}", exc_info=True)

    def host_enum(self) -> Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]:
        """
        Enumerates hosts for different protocols by running tshark commands.
        """
        protocols = {
            'frame': ['frame matches "DESKTOP-*"', 'frame'],
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
            results[protocol] = self.process_output_host_user_enum(output)
            fields[protocol] = field

        return results, fields

    def user_enum(self) -> Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]:
        """
        Enumerates users for different protocols by running tshark commands.
        """
        self.logger.info("Enumerating users for different protocols")
        protocols = {
            'samr': ['samr', 'samr.samr_LookupNames.names'],
            'ldap': ['ldap contains "CN=Users"', 'ldap.baseObject'],
            'kerberos': ['kerberos.CNameString and !(kerberos.CNameString contains "$")', 'kerberos.CNameString'],
            'smb': ['smb', 'ntlmssp.auth.username']
        }
        results = {}
        fields = {}

        try:
            for protocol, params in protocols.items():
                filter, field = params
                output = self._run_tshark_command(['-Y', filter, '-T', 'fields', '-e', field])
                results[protocol] = self.process_output_host_user_enum(output)
                fields[protocol] = field

            return results, fields

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to run TShark command for user enumeration: {e}", exc_info=True)
            return {}, {}

        except ValueError as e:
            self.logger.error(f"Invalid value encountered during user enumeration: {e}", exc_info=True)
            return {}, {}

    def pcap_info(self) -> str:
        """
        Retrieves information about the pcap file using capinfo.
        """
        try:
            self.logger.info("Retrieving pcap information")
            info = self.run_command([capinfo, self.pcap_file])
            self.logger.debug(f"PCAP Info: {info}")
            return info

        except Exception as e:
            self.logger.error(f"Error retrieving pcap info: {e}", exc_info=True)
            return ""

    def iophs(self) -> str:
        """
        Generates Input/Output Protocol Hierarchy Statistics from the pcap file.
        """
        return self._run_tshark_command(['-qz', 'io,phs'])

    def expert_chat(self) -> str:
        """
        Runs TShark to obtain 'expert chat' diagnostic messages from the pcap file.
        """
        try:
            self.logger.info("Running expert_chat method.")
            chat_info = self._run_tshark_command(['-qz', 'expert,chat'])
            self.logger.info("Expert chat information retrieved successfully.")
            return chat_info

        except Exception as e:
            self.logger.error(f"Error in expert_chat method: {e}", exc_info=True)

    def failed_connections(self) -> str:
        """
        Identifies and returns information about failed TCP connection attempts.
        """
        try:
            self.logger.info("Running failed_connections method.")
            failed_conns = self._run_tshark_command(['-Y', 'tcp.analysis.retransmission and tcp.flags eq 0x0002'])
            self.logger.info("Failed connections information retrieved successfully.")
            return failed_conns

        except Exception as e:
            self.logger.error(f"Error in failed_connections method: {e}", exc_info=True)

    def fetch_ip_addresses(self, url='https://blackip.ustc.edu.cn/list.php'):
        """
        Fetches a list of IP addresses from the specified URL.

        This method sends a GET request to the given URL, parses the HTML content
        to extract IP addresses assuming they are located in the third column of a table row.

        Parameters:
        url (str): The URL from which to fetch the IP addresses.

        Returns:
        list: A list of extracted IP addresses.
        """
        try:
            # Log the initiation of a URL request
            self.logger.info("Sending request to URL: %s", url)
            
            # Send a GET request to the specified URL
            response = requests.get(url)
            
            # Raise an exception if the request returned an unsuccessful status code
            response.raise_for_status()
            
            # Log the successful receipt of the response
            self.logger.info("Received response from URL successfully")
            
            # Parse the HTML content of the response
            soup = BeautifulSoup(response.content, 'html.parser')
            ip_addresses = []
            
            # Log the start of the HTML parsing process
            self.logger.info("Starting to parse the HTML content")

            # Iterate over all table rows (<tr>) in the HTML
            for row in soup.find_all('tr'):
                # Extract all table data (<td>) elements from the row
                columns = row.find_all('td')
                
                # Check if the row has more than 2 columns (to avoid index errors)
                if len(columns) > 2:
                    # Append the text from the third column to the ip_addresses list
                    ip_addresses.append(columns[2].text.strip())

            # Log the completion of the HTML parsing
            self.logger.info("Completed parsing HTML content")

            return ip_addresses

        except requests.RequestException as e:
            print(f"An error occurred: {e}")
            return []

    def whois_ip(self) -> None:
        """
        Retrieves WHOIS information for IP addresses.

        This method fetches IP addresses using the fetch_ip_addresses method, compares them
        with a list of unique IPs obtained from a tshark command, and performs WHOIS lookups.
        It also checks if the IPs are blacklisted using DNSBL and excludes IPs from specified AS names.

        Output:
        Prints WHOIS information, blacklisted IPs, and any suspicious IPs found.
        """
        fetch_ips = self.fetch_ip_addresses()
        blackips = set(fetch_ips)
        excluded_as_names = ["MICROSOFT-CORP-MSN-AS-BLOCK", "AKAMAI-AS, US", "GOOGLE, US", "CLOUDFLARENET, US",
                             "AMAZON-02, US"]
        excluded_ips = []
        blacklisted_ips = {}

        self.logger.info("Retrieving WHOIS information using the whois_ip method.")
        self.logger.warning(
            "[!!] IPs from top CDN providers are deliberately excluded in order to filter out noise typically associated with high-traffic CDN providers.")

        try:
            check_tshark_output = self._run_tshark_command(['-T', 'fields', '-e', 'ip.dst'])
            tshark_dest_ips = check_tshark_output.strip().splitlines()
            unique_ips = set(filter(None, tshark_dest_ips))
            suspicious_ips = set(blackips) & set(unique_ips)

            for ip in unique_ips:
                try:
                    if ipaddress.ip_address(ip).is_private:
                        continue

                except ValueError as e:
                    self.logger.error(f"Invalid IP address format: {ip} - {e}")
                    continue  # Skip invalid IP formats

                whois_info = self.run_command(['whois', '-h', 'whois.cymru.com', ip])

                # Only exclude and skip DNSBL checks if IP is in excluded AS names
                if any(excluded_as in whois_info for excluded_as in excluded_as_names):
                    #self.logger.info(f"Excluding IP {ip} based on WHOIS info")
                    excluded_ips.append(ip)
                else:
                    # Print WHOIS info for IPs not in the exclusion list
                    print(whois_info)

                    # Check if IP is blacklisted using DNSBL
                    reversed_ip = '.'.join(ip.split('.')[::-1])
                    dnsbl_services = [
                        "zen.spamhaus.org",
                        "cbl.abuseat.org",
                        "b.barracudacentral.org",
                        "dnsbl-1.uceprotect.net",
                        "spam.dnsbl.sorbs.net"
                    ]

                    is_blacklisted = False
                    for service in dnsbl_services:
                        query = f"{reversed_ip}.{service}"
                        try:
                            dns.resolver.resolve(query, 'A')
                            is_blacklisted = True
                            blacklisted_ips.setdefault(service, []).append(ip)
                        except dns.resolver.NXDOMAIN:
                            #self.logger.info(f"IP address {ip} not found in {service}")
                            pass
                        except Exception as e:
                            if "The DNS operation timed out" not in str(e):
                                self.logger.error(f"Error during reverse IP lookup for {service}: {e}")

            # Print blacklisted IPs grouped by service
            if blacklisted_ips:
                print("\nIPs found in DNSBL blackhole lists:")
                for service, ips in blacklisted_ips.items():
                    print(f"\nService: {service}")
                    for ip in ips:
                        print(f"  {ip}")
            else:
                print("\nNo IPs found in DNSBL blackhole lists.")

            if len(suspicious_ips) == 0:
                print("\n")
                print("service: University of Science and Technology of China's IP blacklist:")
                print('[*] Good news. Nothing found :-)')
            else:
                print("\n")
                print('service: University of Science and Technology of China (USTC) blacklist:')
                print('[!!] The following suspicious IPs were found:')
                for ip in suspicious_ips:
                    print(ip)

            # Print the list of excluded IPs
            if excluded_ips:
                print("\nExcluded IPs:")
                for ip in excluded_ips:
                    print(ip)
            else:
                print("\nNo IPs were excluded.")

            print("\n")

            self.logger.info("WHOIS information retrieved for IPs successfully.")

        except Exception as e:
            self.logger.error(f"Error retrieving WHOIS information: {e}", exc_info=True)

    def arp_thunt(self) -> Tuple[str, str]:
        """
        Searches for ARP poisoning attacks within the network traffic data.
        """
        self.logger.info("Searching for ARP poisoning attacks")
        try:
            arp_duplicate_address = self._run_tshark_command(
                ['-Y', 'arp.duplicate-address-detected', '-T', 'fields', '-e', 'arp.duplicate-address-detected'])
            arp_packet_storm = self._run_tshark_command(
                ['-Y', 'arp.packet-storm-detected', '-T', 'fields', '-e', 'arp.packet-storm-detected'])
            self.logger.info("ARP poisoning search completed")
            return arp_duplicate_address, arp_packet_storm

        except Exception as e:
            self.logger.error(f"Error during ARP poisoning search: {e}", exc_info=True)
            return "", ""

    def user_agent(self) -> Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]:
        """
        Extracts and counts occurrences of HTTP user agents from network traffic data.

        This method executes a TShark command to capture the 'http.user_agent' fields from the pcap file.
        It then processes this output to count the occurrences of each unique user agent, providing insights
        into the different types of clients that have interacted with the network.
        """
        self.logger.info("Extracting HTTP user agents")
        try:
            cmd = ['-T', 'fields', '-e', 'http.user_agent']
            output = self._run_tshark_command(cmd)
            user_agents = [ua for ua in output.strip().split('\n') if ua.strip()]
            user_agent_counts = Counter(user_agents).most_common()
            formatted_results = {"HTTP User Agents": list(user_agent_counts)}
            fields_dict = {"HTTP User Agents": "User Agent"}
            self.logger.info("HTTP user agents extracted successfully")
            return formatted_results, fields_dict

        except Exception as e:
            self.logger.error(f"Error extracting HTTP user agents: {e}", exc_info=True)
            return {}, {}

    def web_basic(self) -> str:
        """
        Extracts web traffic information from the pcap file.
        """
        self.logger.info("Extracting web traffic information")
        print('')
        try:
            web_traffic_info = self._run_tshark_command(
                ['-Y', '(http.request or http.response or tls.handshake.type eq 1) and !(ssdp)'])
            self.logger.info("Web traffic information extracted successfully")
            return web_traffic_info

        except Exception as e:
            self.logger.error(f"Error in extracting web traffic information: {e}", exc_info=True)
            return ""

    @staticmethod
    def display_options(services_list):
        """
        Display a list of service options with color formatting.
        """
        header_color = Color.BOLD + Color.LIGHTYELLOW
        service_name_color = Color.BOLD + Color.AQUA

        print(f"\n{header_color}Available Options:{Color.END}")
        for service in services_list:
            print(f"{service_name_color}{service}{Color.END}")

    @staticmethod
    def highlight_special_chars(text: str, highlight_color: str) -> str:
        """
        Highlight specific special characters in the input text with the given color.
        """
        special_chars = ['(', ')', '/']
        colored_text = ""
        for char in text:
            if char in special_chars:
                colored_text += f"{highlight_color}{char}{Color.END}"
            else:
                colored_text += char
        return colored_text

    @staticmethod
    def highlight_brackets_and_colorize_words(text: str, bracket_color: str, word_color: str) -> str:
        """
        Highlight brackets and colorize words inside the brackets in the given text.
        """
        # Split the text by '[' and ']'
        parts = text.split('[')
        highlighted_text = parts[0]

        for part in parts[1:]:
            if ']' in part:
                word, rest = part.split(']', 1)
                
                # Apply colors to the brackets and the word inside
                highlighted_word = f"{bracket_color}[{Color.END}{word_color}{word}{Color.END}{bracket_color}]{Color.END}"
                highlighted_text += highlighted_word + rest
            else:
                highlighted_text += '[' + part

        return highlighted_text

    def get_dcerpc_abuse_info(self) -> None:
        """
        Retrieves and prints abuse information for a specified DCERPC service and method.
        Allows users to list all services, get detailed information, or search across all services.
        """
        while True:
            options_text = "Options: [list] all services, [methods] to list methods of a service, [search] for a keyword, [exit] to quit."
            colored_options_text = self.highlight_brackets_and_colorize_words(options_text, Color.LIGHTGREEN, Color.BLUE)

            prompt_text = "Enter choice (list/methods/search/exit) or service name: "
            colored_prompt_text = self.highlight_special_chars(prompt_text, Color.LIGHTRED)

            print(f"\n{colored_options_text}")
            print(colored_prompt_text, end="")  # 'end=""' to keep the input on the same line

            user_input = input().lower()

            if user_input == 'exit':
                break
            elif user_input == 'list':
                services = get_dcerpc_info(list_services=True)
                self.display_options(services)
            elif user_input == 'search':
                keyword = input("Enter a specific keyword to search (e.g., a part of method name, specific attack type, detail in notes): ").strip()
                if not keyword:
                    print("Please enter a valid keyword to search.")
                    continue
                search_results = enhanced_search(keyword, dcerpc_services)
                if search_results:
                    formatted_results = "\n".join(search_results)
                    self.paginate_output(formatted_results)
                else:
                    print("No results found for the keyword.")
            elif user_input == 'methods':
                service_name = input("Enter the service name to list methods: ")
                list_methods(service_name, dcerpc_services)
            else:
                service_name_input = user_input
                opnum_input = get_input_opnum()
                try:
                    method, note, attack_ttp, attack_type, ioc = get_dcerpc_info(service_name_input, opnum_input)
                    if method:
                        self.print_detailed_info(service_name_input, opnum_input, method, note, attack_ttp, attack_type,
                                                 ioc)
                    else:
                        print("Service or method not found.")
                except ValueError as e:
                    print(f"Error: {e}")

    def print_detailed_info(self, service_name, opnum, method, note, attack_ttp, attack_type, ioc):
        """
        Prints detailed information about a specific DCERPC service method.
        """
        # Print the opnum and method name
        print(f"{Color.BOLD + Color.CYAN}- Opnum {opnum}:{Color.END}")
        print(f"  {Color.BOLD + Color.AQUA}Method{Color.END}: {Color.GREY}{method}{Color.END}")

        # Print the note with proper indentation for multiline text
        print(f"  {Color.BOLD + Color.AQUA}Note{Color.END}: ", end='')
        note_lines = note.split('\n')
        if len(note_lines) > 1:
            print(f"{Color.GREY}{note_lines[0].strip()}{Color.END}")
            for line in note_lines[1:]:
                print(f"         {Color.GREY}{line.strip()}{Color.END}")
        else:
            print(f"{Color.GREY}{note.strip()}{Color.END}")

        print(f"  {Color.BOLD + Color.AQUA}Attack TTP{Color.END}: {Color.GREY}{attack_ttp.strip()}{Color.END}")
        print(f"  {Color.BOLD + Color.AQUA}Attack Type{Color.END}: {Color.GREY}{attack_type.strip()}{Color.END}")
        print(f"  {Color.BOLD + Color.AQUA}IOC{Color.END}: {Color.GREY}{ioc.strip()}{Color.END}")

    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ Data Extraction྇ M྇e྇t྇h྇o྇d྇s྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ Data Presentation༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def display_results(self, results: Dict[str, List[Tuple[str, int]]], fields: Dict[str, str]) -> None:
        """
        Displays the results of the tshark command processing in a formatted manner using rich.
        """
        self.logger.info("Displaying results")
        try:
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
                    #table.add_row(str(count), host)
                    table.add_row(str(count), host, style=style)
                console.print(table)
            self.logger.debug(f"Results displayed for protocols: {list(results.keys())}")
        except Exception as e:
            self.logger.error(f"Error displaying results: {e}", exc_info=True)

    def find_beacons(self, ip_address: Optional[str] = None, interval_frequency: Optional[str] = None) -> None:
        """
        Identifies beacon-like traffic patterns for a given IP address and interval frequency.

        Utilizes TShark for network traffic analysis and matplotlib for visualizing the patterns. Prompts for user
        input if ip_address or interval_frequency are not provided.
        """
        self.logger.info("Identifying beacon-like traffic patterns")
        try:
            if ip_address is None:
                ip_address = input("Enter the IPv4 address you wish to look for patterns to determine beacons: ")
                while not is_valid_ipv4_address(ip_address):
                    self.logger.warning(f"Invalid IP address input: {ip_address}")
                    ip_address = input("Invalid IP. Please enter a valid IPv4 address: ")
            if interval_frequency is None:
                interval_frequency = input("Enter the interval frequency (in seconds): ")
                while not is_valid_interval(interval_frequency):
                    self.logger.warning(f"Invalid interval frequency input: {interval_frequency}")
                    interval_frequency = input("Invalid interval. Please enter a valid interval frequency in seconds: ")
            self.logger.debug(f"Running TShark command for beacon-like pattern detection on IP: {ip_address}")
            tshark_output = self._run_tshark_command(
                ['-qz',
                 f'io,stat,{interval_frequency},MIN(frame.time_relative)frame.time_relative,ip.addr=={ip_address},MAX(frame.time_relative)frame.time_relative']
            )
            print("TShark Output:", tshark_output)
            self.logger.debug("Processing TShark output for plotting")

            # Process TShark output to extract data for plotting
            times, frames, bytes_data = self._process_tshark_output(tshark_output)
            
            # Calculate total duration based on the time intervals
            total_duration = times[-1] - times[0] if times else 0
            
            # Create figure and axis objects
            fig, ax1 = plt.subplots(figsize=(15, 8))
            fig.patch.set_facecolor('lightgray')
            ax1.set_facecolor('lightblue')
            
            # Plotting frames
            frame_line, = ax1.plot(times, frames, marker='o', color='blue', label='Frame Count')
            
            # Set x-axis label
            ax1.set_xlabel(f"Time Intervals (s) - Total Duration: {total_duration} s", labelpad=15)
            
            # Add additional text below the x-axis label for the chosen interval frequency
            ax1.text(0.5, -0.15, f"Interval Frequency: {interval_frequency} s",transform=ax1.transAxes, ha='center', va='center', fontsize=10)
            
            # Plotting bytes on a secondary y-axis
            ax2 = ax1.twinx()
            bytes_line, = ax2.plot(times, bytes_data, marker='x', color='red', label='Byte Count')
            
            # Ensure this matches ax1 for a consistent look
            ax2.set_facecolor("lightblue")
            
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
            self.logger.debug(f"Beacon-like traffic patterns identified and plotted for IP: {ip_address}")

        except ValueError as e:
            self.logger.error(f"Error in input validation for beacon-like pattern detection: {e}", exc_info=True)
        except Exception as e:
            self.logger.error(f"Error identifying beacon-like traffic patterns: {e}", exc_info=True)

    def _process_tshark_output(self, output: str):
        """
        Processes the output from the TShark command to extract time intervals, frame counts, and byte counts.

        The function assumes the output is formatted in a table where each row represents a time interval
        and the columns include the maximum and minimum frame times, the number of frames, and the number
        of bytes.
        """
        times = []
        frames = []
        bytes_data = []

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
                parts = line.split('|')
                if len(parts) >= 6:
                    try:
                        interval = parts[1].strip()
                        frame_count = parts[3].strip()
                        byte_count = parts[4].strip()
                        
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

    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ Data Presentation྇ M྇e྇t྇h྇o྇d྇s྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ User Interaction M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def display_filter(self) -> str:
        """
        Applies a user-specified display filter and returns the filtered output from the pcap file.
        """
        self.logger.info("Applying display filter")
        try:
            get_input = input("Enter a valid display filter: ")
            self.logger.debug(f"Display filter entered: {get_input}")

            view_verbose = input("Expand the packet layers? (Y/N): ")
            view_all_pkts = input("View all packets? (Y/N): ")
            custom_fields = input("Specify custom fields? (Y/N): ")

            options = ['-Y', get_input]

            if view_verbose.lower() == "y":
                options.append('-V')
                self.logger.debug("Verbose packet layer expansion enabled")
            if view_all_pkts.lower() == "n":
                how_many_pkts = input("How many packets do you want to see? ")
                options.extend(['-c', how_many_pkts])
                self.logger.debug(f"Packet limit set to: {how_many_pkts}")
            elif view_all_pkts.lower() == "y":
                self.logger.debug("All packets will be displayed")

            # Call _run_tshark_command with or without custom fields
            if custom_fields.lower() == "y":
                custom_field_options = input("Enter one or more custom field options (comma-separated): ")
                self.logger.debug(f"Custom fields specified: {custom_field_options}")
                output = self._run_tshark_command(options, custom_fields=custom_field_options)
                
                # Process the output if custom fields were specified
                non_blank_lines = [line for line in output.splitlines() if line.strip()]
                sorted_output = sorted(non_blank_lines, key=lambda x: x.split()[0])
                counts = Counter(sorted_output)
                sorted_by_count_output = '\n'.join(f'{count} {line}' for line, count in counts.most_common())
                self.logger.debug("Display filter applied with custom fields")

                return sorted_by_count_output

            else:
                output = self._run_tshark_command(options)
                self.logger.debug("Display filter applied without custom fields")
                return output

        except Exception as e:
            self.logger.error(f"Error applying display filter: {e}", exc_info=True)
            return ""

    def dns_hunt(self) -> None:
        """
        Searches for DNS queries or responses involving a specific domain within the network traffic.
        """
        self.logger.info("Starting DNS hunt")
        while True:
            try:
                ask_dns = input('Enter the domain you want to search for, enclosed in double quotes (".onion", "wtfismyip.com"):\nOr type `exit` to quit: ')
                if ask_dns.lower() == 'exit':
                    break
                result = self._run_tshark_command(['-Y', 'dns matches ' + ask_dns])
                print(result)
            except subprocess.SubprocessError as e:
                self.logger.error(f"A subprocess error occurred in dns_hunt: {e}", exc_info=True)
            except Exception as e:
                self.logger.error(f"An unexpected error occurred in dns_hunt: {e}", exc_info=True)
            print("\n")

    def viewframe_getstream(self) -> str:
        """
        Retrieves the TCP stream index for a specified frame number.
        """
        self.logger.info("Retrieving TCP stream index for frame")
        try:
            ask_frame = input("Enter the frame number: ")
            stream_info = self._run_tshark_command(
                ['-Y', f"frame.number == {ask_frame}", '-T', 'fields', '-e', 'tcp.stream'])
            self.logger.debug(f"TCP stream index retrieved for frame {ask_frame}")
            return stream_info
        except Exception as e:
            self.logger.error(f"Error retrieving TCP stream index for frame: {e}", exc_info=True)
            return ""

    def tcp_stream(self) -> str:
        """
        Follows a specified TCP stream index and returns its contents.
        """
        self.logger.info("Following TCP stream")
        try:
            get_tcp_stream_number = input_prompt("Which TCP stream index would you like to see? ", is_valid_digit)
            tcp_stream_info = self._run_tshark_command(['-qz', f'follow,tcp,ascii,{get_tcp_stream_number}'])
            self.logger.info("TCP stream followed successfully")
            return tcp_stream_info
        except Exception as e:
            self.logger.error(f"Error in following TCP stream: {e}", exc_info=True)
            return ""

    def http_stream(self) -> str:
        """
        Follows a specified HTTP stream and returns its contents.
        """
        try:
            self.logger.info("Running http_stream method.")
            get_http_stream_number = input_prompt("Which HTTP stream index would you like to see? ", is_valid_digit)
            http_stream_info = self._run_tshark_command(['-qz', f'follow,http,ascii,{get_http_stream_number}'])
            self.logger.info("HTTP stream information retrieved successfully.")
            return http_stream_info
        except Exception as e:
            self.logger.error(f"Error in http_stream method: {e}", exc_info=True)

    def paginate_output(self, output: str, lines_per_page: int = 25) -> None:
        """
        Paginates the output for better readability.
        """
        lines = output.split('\n')
        for i in range(0, len(lines), lines_per_page):
            print('\n'.join(lines[i:i + lines_per_page]))
            if i + lines_per_page < len(lines):
                cont = input("Press Enter to continue, type 'stop' to halt: ").lower().strip()
                if cont == 'stop':
                    break

    def flow_any(self) -> None:
        """
        Continuously prompts the user for a valid display filter to retrieve communication flow statistics between two endpoints
        using the tshark tool. If the user inputs 'help', its misspellings, or a single 'h', sample input values are displayed.
        The user can exit the loop by typing 'exit'.
        """
        help_examples = [
            "Example 1: dns matches \".xyz*\"",
            "Example 2: ip.addr==10.12.19.1",
            "Example 3: !(dns matches \".xyz*\")",
            "Example 4: tcp.stream eq 1"
        ]
        while True:
            try:
                self.logger.info("Getting flow statistics.")
                prompt1 = input(
                    'To see the communication flows between two endpoints, enter a valid display filter.\n\n'
                    'Enter "help" for examples, "exit" to go back to the main menu, or a valid display filter: ')

                if prompt1 == 'exit':
                    break

                help_variations = {'help', 'hlep', 'hepl', 'ehlp', 'hel', 'hlp', 'h'}

                if prompt1 in help_variations:
                    print("\n".join(help_examples))
                    continue

                prompt2 = self._run_tshark_command(['-qz', f'flow,any,standard,{prompt1}'])
                self.paginate_output(prompt2)

            except Exception as e:
                self.logger.error(f"Error in flow_any method: {e}", exc_info=True)
                raise

    def show_packets(self) -> None:
        """
        Continuously prompts the user to display network packets, either all or filtered by a specific protocol.
        """
        while True:
            try:
                get_proto = input("Show all packets? (yes or no, or 'exit' to quit) ")
                self.logger.info("Displaying network packets")
                if get_proto.lower() == 'exit':
                    break
                elif get_proto.lower() == "no":
                    which_proto = input("Which protocol would you like to see all packets for? ")
                    packets = self._run_tshark_command(['-Y', which_proto])
                    print("\n")
                    print(packets)
                elif get_proto.lower() == "yes":
                    packets = self._run_tshark_command([])
                    print("\n")
                    print(packets)
                else:
                    print("Invalid input. Please enter 'yes' or 'no'.")
            except subprocess.SubprocessError as e:
                self.logger.error(f"A subprocess error occurred in show_packets: {e}", exc_info=True)
            except Exception as e:
                self.logger.error(f"An unexpected error occurred in show_packets: {e}", exc_info=True)

    def statistics(self) -> None:
        """
        Continuously prompts the user to choose a type of network statistics to view, such as conversations,
        server response times, tree statistics, and host listings.
        """
        self.logger.info("Viewing network statistics")
        while True:
            which_stats = input(
                f"{Color.LAVENDER}What type of statistics do you want to view (conv/hosts/srt/tree)?\nEnter your choice or 'exit' to quit:  {Color.END}: ")
            if which_stats.lower() == 'exit':
                break

            try:
                def conversations() -> None:
                    """
                    Prompt the user to select a protocol and display the corresponding conversation statistics
                    """
                    self.logger.info("Viewing conversation statistics")
                    try:
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
                            self.logger.debug(f"Conversations displayed for protocol: {ask_protocol}")
                        else:
                            self.logger.warning(f"Unsupported protocol for conversations: {ask_protocol}")
                    except Exception as er:
                        self.logger.error(f"Error displaying conversations: {er}", exc_info=True)

                def _server_resp_times() -> None:
                    """
                    Display server response times for selected protocols.
                    """
                    self.logger.info("Viewing server response times")
                    try:
                        ask_protocol = input(
                            f"{Color.LAVENDER}Which protocol would you like to see server response times for? "
                            f"(icmp/ldap/smb/smb2/srvsvc/drsuapi/lsarpc/netlogon/samr/svcctl/wkssvc){Color.END}: ")
                        protocol_commands: Dict[str, List[str]] = {
                            'icmp': ['icmp,srt'],
                            'ldap': ['ldap,srt'],
                            'smb': ['smb,srt'],
                            'smb2': ['smb2,srt'],
                            'drsuapi': ['dcerpc,srt,e3514235-4b06-11d1-ab04-00c04fc2dcd2,4.0'],
                            'lsarpc': ['dcerpc,srt,12345778-1234-abcd-ef00-0123456789ab,0.0'],
                            'netlogon': ['dcerpc,srt,12345678-1234-abcd-ef00-01234567cffb,1.0'],
                            'samr': ['dcerpc,srt,12345778-1234-ABCD-EF00-0123456789AC,1.0'],
                            'srvsvc': ['dcerpc,srt,4b324fc8-1670-01d3-1278-5a47bf6ee188,3.0'],
                            'svcctl': ['dcerpc,srt,367abb81-9844-35f1-ad32-98f038001003,2.0'],
                            'wkssvc': ['dcerpc,srt,6BFFD098-A112-3610-9833-46C3F87E345A,1.0']
                        }
                        if ask_protocol in protocol_commands:
                            tshark_command = ['-qz'] + protocol_commands[ask_protocol]
                            print(self._run_tshark_command(tshark_command))
                            self.logger.debug(f"Server response times displayed for protocol: {ask_protocol}")
                        else:
                            self.logger.warning(f"Unsupported protocol for server response times: {ask_protocol}")
                    except Exception as er:
                        self.logger.error(f"Error displaying server response times: {er}", exc_info=True)

                def tree() -> None:
                    """
                    Display tree statistics for selected protocols.
                    """
                    self.logger.info("Viewing tree statistics")
                    try:
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
                            self.logger.debug(f"Tree statistics displayed for protocol: {ask_protocol}")
                        else:
                            self.logger.warning(f"Unsupported protocol for tree statistics: {ask_protocol}")
                    except Exception as er:
                        self.logger.error(f"Error displaying tree statistics: {er}", exc_info=True)

                def hosts() -> None:
                    """
                    Display host listings.
                    """
                    self.logger.info("Viewing host listings")
                    try:
                        tshark_command = ['-qz', 'hosts,ip']
                        print(self._run_tshark_command(tshark_command))
                        self.logger.debug("Host listings displayed")
                    except Exception as er:
                        self.logger.error("Error displaying host listings", exc_info=True)

                # Mapping of statistics types to the corresponding function calls
                stats_functions: Dict[str, Any] = {
                    'conv': conversations,
                    'srt': _server_resp_times,
                    'tree': tree,
                    'hosts': hosts
                }
                func = stats_functions.get(which_stats)
                self.logger.debug(f"Network statistics displayed for: {which_stats}")
                if func:
                    func()
                else:
                    self.logger.warning(f"Unsupported statistics type: {which_stats}")
            except Exception as e:
                self.logger.error(f"Error in viewing statistics for {which_stats}: {e}", exc_info=True)
            print("\n")

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
            result = self.read_verbose()
            if isinstance(result, (tuple, list)) and len(result) == 2:
                verbose_results, verbose_fields = result
                if verbose_results is not None and verbose_fields is not None:
                    self.display_results(verbose_results, verbose_fields)
                else:
                    print("Unable to display results due to missing data.")
            else:
                print("Invalid or unexpected data format from read_verbose.")
        except ValueError as e:
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
            result = self.user_agent()
            
            # Check if the result is a tuple or list with two elements
            if isinstance(result, (tuple, list)) and len(result) == 2:
                user_agent_results, user_agent_fields = result
                
                # Check if user_agent_results and user_agent_fields are not None before using them
                if user_agent_results is not None and user_agent_fields is not None:
                    self.display_results(user_agent_results, user_agent_fields)
                else:
                    print("Unable to display results due to missing data.")
            else:
                print("Invalid or unexpected data format from user_agent.")
        except ValueError as e:
            print(f"Caught an error: {e}")

    def read_verbose(self) -> Union[Tuple[Dict[Any, List[Tuple[Any, int]]], Dict[Any, Any]], str]:
        """
        Reads and processes verbose information based on a user-specified protocol in a TShark analysis.
        """
        self.logger.info("Reading verbose information")

        # Dictionary mapping protocol names to their corresponding field names and display filters.
        protocol_args = {
            'eth': (['eth.addr.oui_resolved'], 'eth'),                  # Ethernet protocol, filter on OUI addresses
            'smb2': (['smb2.filename'], 'smb2.filename'),               # SMB2 protocol, filter on filenames
            'dns': (['dns.qry.name'], 'dns and !(dns.qry.name matches "microsoft.com*") && !(dns.qry.name matches "msedge.net*") && !(dns.qry.name matches "microsoftonline.com*") && !(dns.qry.name matches "msftncsi.com*") && !(dns.qry.name matches "windows.com*")'),                           # DNS protocol, filter on query names
            'tls': (['tls.handshake.extensions_server_name'], 'tls and !(tls.handshake.extensions_server_name matches "microsoft.com*") && !(tls.handshake.extensions_server_name matches "msedge.net*") && !(tls.handshake.extensions_server_name matches "microsoftonline.com*")'),   # TLS protocol, filter on server name
            'http': (['http.request.full_uri'], 'http'),                # HTTP protocol, filter on requests
        }
        try:
            # Prompt the user to select a protocol to search within the pcap file.
            ask_protocol = input(f"{Color.CYAN}Choose a protocol to search (dns, eth, http, smb2, tls){Color.END}: ")

            if ask_protocol in protocol_args:
                fields, display_filter = protocol_args[ask_protocol]
                output = self._process_protocol(display_filter, fields)
                processed_output = self.process_output_read_verbose(output, ask_protocol)
                fields_dict = {ask_protocol: "Description"}
                self.logger.debug(f"Verbose information read for protocol: {ask_protocol}")
                return processed_output, fields_dict
            else:
                raise ValueError(f"Unknown protocol: {ask_protocol}")

        except ValueError as err:
            self.logger.error(f"Error reading verbose information: {err}", exc_info=True)
            return f"An error occurred: {err}. Please enter a valid protocol."
        except Exception as e:
            self.logger.error(f"Unexpected error in read_verbose: {e}", exc_info=True)
            return "An unexpected error occurred."


    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ User Interaction M྇e྇t྇h྇o྇d྇s྇


if __name__ == "__main__":
    pass
