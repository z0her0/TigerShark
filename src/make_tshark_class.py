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

import logging                                                  # Logging utility for debugging and error tracking
import sys                                                      # System-specific parameters and functions
import os                                                       # Operating system interfaces
import subprocess                                               # Process creation and management
from collections import Counter                                 # Container for counting hashable objects
from typing import Optional, Dict, List, Tuple, Any, Union      # Type hinting and generic types for better code clarity
from logging.handlers import RotatingFileHandler                # Logging handler for log file rotation

import matplotlib.pyplot as plt                                 # Plotting library for creating graphs and charts
from rich.table import Table                                    # Rich library component for creating formatted tables
from rich.console import Console                                # Rich library component for enhanced console output

from dcerpc_method_abuse_notes import get_dcerpc_info           # MSRPC to ATT&CK lookup table
from make_colorful import Color, ColorRandomRGB                 # Terminal color output utility
from make_helpers import (
    input_prompt,                                               # Standardized user input prompt
    is_valid_interval,                                          # Interval validation
    is_valid_digit,                                             # Digit validation
    is_valid_ipv4_address,                                      # IPv4 address validation
    set_tshark_path,                                            # Set the path to the tshark application
    get_input_opnum,                                            # Get and validate user input
)


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

        Args:
            log_file (str): Path to the log file.
            level (str): Logging level as a string, e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'.
            log_format (str): Format for the logging messages.
            max_log_size (int): Maximum size of the log file in bytes before it is rotated.
            backup_count (int): The number of backup files to keep.
            suppress_output (bool): If True, suppresses console output.

        Returns:
            logging.Logger: A configured logger object.
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

        Args:
            profile_name (str): The name of the Wireshark profile to check.

        Returns:
            bool: True if the profile directory exists, False otherwise.
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

        Args:
            options (List[str]): Command-line options for tshark.
            display_filter (Optional[str]): Display filter string for tshark.
            custom_fields (Optional[str]): Custom fields to be included in the tshark output.
            profile_name (Optional[str]): Name of the Wireshark profile to use (defaults to 'THunt').

        Returns:
            str: The standard output from the tshark command, or an empty string if an error occurs.
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

            self.logger.info("TShark command executed successfully")
            return completed_process.stdout.decode()

        except subprocess.CalledProcessError as e:
            self.logger.error(f"TShark command execution failed: {e}", exc_info=True)
            return ""

    def _process_protocol(self, display_filter: str, fields: List[str]) -> str:
        """
        Constructs and executes a TShark command to extract specific fields from packets
        that match a given display filter.

        Args:
            display_filter (str): The display filter to apply to the TShark command.
            fields (List[str]): A list of fields to extract from the packet data.

        Returns:
            str: The output from the TShark command as a string.
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

        Returns:
            str: The output from the tshark command, which contains information about the detected TLS handshakes.
                 It will return an empty string if an exception occurs.

        Raises:
            Exception: If there's an issue executing the tshark command, an exception will be logged with the error message.
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
        Returns:
            Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]: A tuple containing the results and the
                                                                    fields used for each protocol.
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
        Returns:
            Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]: A tuple containing the results and the
                                                                    fields used for each protocol.
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

    def whois_ip(self) -> None:
        """
        Retrieves WHOIS information for unique destination IP addresses found in the pcap file
        and lists IPs belonging to specified Autonomous Systems at the end.
        """
        excluded_as_names = ["MICROSOFT-CORP-MSN-AS-BLOCK", "NA", "AKAMAI-AS, US", "GOOGLE, US", "CLOUDFLARENET, US",
                             "AMAZON-02, US"]
        excluded_ips = []

        self.logger.info("Retrieving WHOIS information using the whois_ip method.")
        try:
            check_tshark_output = self._run_tshark_command(['-T', 'fields', '-e', 'ip.dst'])
            tshark_dest_ips = check_tshark_output.strip().splitlines()
            unique_ips = set(filter(None, tshark_dest_ips))

            for ip in unique_ips:
                whois_info = self.run_command(['whois', '-h', 'whois.cymru.com', ip])

                if any(excluded_as in whois_info for excluded_as in excluded_as_names):
                    excluded_ips.append(ip)
                else:
                    print(whois_info)

            if excluded_ips:
                print("\nExcluded IPs:")
                for ip in excluded_ips:
                    print(ip)

            print("\n")

            self.logger.info("WHOIS information retrieved for IPs successfully.")

        except Exception as e:
            self.logger.error(f"Error retrieving WHOIS information: {e}", exc_info=True)

    def arp_thunt(self) -> Tuple[str, str]:
        """
        Searches for ARP poisoning attacks within the network traffic data.

        Returns:
            Tuple[str, str]: A tuple containing strings with ARP duplicate address and packet storm data.
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

        Returns:
            Tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]: A tuple containing two dictionaries.
            The first dictionary maps a descriptive key to a list of tuples, where each tuple contains a user
            agent string and its count. The second dictionary provides a mapping for field descriptions used in
            the output.
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
        Extracts basic web traffic information from the pcap file.

        Returns:
            str: A string representation of basic web traffic information.
        """
        self.logger.info("Extracting basic web traffic information")
        print('')
        try:
            web_traffic_info = self._run_tshark_command(
                ['-Y', '(http.request or http.response or tls.handshake.type eq 1) and !(ssdp)'])
            self.logger.info("Web traffic information extracted successfully")
            return web_traffic_info
        except Exception as e:
            self.logger.error(f"Error in extracting web traffic information: {e}", exc_info=True)
            return ""

    def get_dcerpc_abuse_info(self) -> None:
        """
        Retrieves and prints abuse information for a specified DCERPC service and method.
        """
        self.logger.info("Retrieving DCERPC abuse information")
        service_name_input = input("Enter the service (e.g., samr, drsuapi, netlogon, lsarpc, srvsvc, svcctl): ")
        opnum_input = get_input_opnum()
        try:
            method, note, attack_ttp, attack_type, ioc = get_dcerpc_info(service_name_input, opnum_input)
            if method:
                print(f"{Color.AQUA}Info for {service_name_input} opnum {opnum_input}:{Color.END}")
                print("")
                print(f"{Color.UNDERLINE}Function{Color.END}: {method}")
                print("")
                print(f"{Color.UNDERLINE}Attack TTP{Color.END}: {attack_ttp}")
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
            self.logger.error(f"Error retrieving DCERPC abuse information: {e}", exc_info=True)
            method, note, attack_ttp, attack_type, ioc = None, None, None, None, None

    # E྇N྇D྇ S྇E྇C྇T྇I྇O྇N྇:྇ Data Extraction྇ M྇e྇t྇h྇o྇d྇s྇

    # B༙྇E༙྇G༙྇I༙྇N༙྇ S༙྇E༙྇C༙྇T༙྇I༙྇O༙྇N༙྇:༙྇ Data Presentation༙྇ M༙྇e༙྇t༙྇h༙྇o༙྇d༙྇s༙྇

    def display_results(self, results: Dict[str, List[Tuple[str, int]]], fields: Dict[str, str]) -> None:
        """
        Displays the results of the tshark command processing in a formatted manner using rich.
        Args:
            results (Dict[str, List[Tuple[str, int]]]): The processed results from tshark commands.
            fields (Dict[str, str]): The fields used for each protocol in the tshark command.
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
                    # table.add_row(str(count), host)
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

        Parameters:
        ip_address (Optional[str]): The IPv4 address for analysis. If None, prompts for input.
        interval_frequency (Optional[str]): Interval frequency in seconds for traffic pattern analysis. If None,
        prompts for input.

        Returns:
        None: Outputs a matplotlib plot of the traffic analysis and logs the process.

        Raises:
        ValueError: On invalid input for IP address or interval frequency.
        Exception: On issues executing TShark command or processing its output.

        Note:
        This function requires matplotlib for plotting the analysis results.
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

        Parameters:
        output (str): The raw string output from the TShark command.

        Returns:
        tuple: A tuple containing three lists:
            times (list of float): A list of interval start times extracted from the output.
            frames (list of int): A list of frame counts corresponding to each time interval.
            bytes_data (list of int): A list of byte counts corresponding to each time interval.
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

        Returns:
            str: Filtered output based on the user's specified display filter.
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

        Returns:
            str: The TCP stream index associated with the specified frame number.
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

        Returns:
            str: The content of the followed TCP stream.
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

        Returns:
            str: The content of the followed HTTP stream.
        """
        try:
            self.logger.info("Running http_stream method.")
            get_http_stream_number = input_prompt("Which HTTP stream index would you like to see? ", is_valid_digit)
            http_stream_info = self._run_tshark_command(['-qz', f'follow,http,ascii,{get_http_stream_number}'])
            self.logger.info("HTTP stream information retrieved successfully.")
            return http_stream_info
        except Exception as e:
            self.logger.error(f"Error in http_stream method: {e}", exc_info=True)

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
                    self.logger.info("Viewing server response times")
                    try:
                        ask_protocol = input(
                            f"{Color.LAVENDER}Which protocol would you like to see server response times for? "
                            f"(icmp/ldap/smb/smb2/srvsvc/drsuapi/lsarpc/netlogon/samr/svcctl){Color.END}: ")
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
                            'svcctl': ['dcerpc,srt,367abb81-9844-35f1-ad32-98f038001003,2.0']
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

        Returns:
            Union[Tuple[Dict, Dict], str]: A tuple containing processed verbose results and fields if successful,
                                           or an error message string in case of an exception.
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
