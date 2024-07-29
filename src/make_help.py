"""
WORK IN PROGESS

Displays the general help message and then prompts the user for an option to display detailed help.
"""
from make_colorful import Color


def show_help(option: int = None) -> None:
    """
    Displays detailed help for each menu option in the TigerShark CLI application or a specific option if provided.

    Args:
        option (str, optional): The menu option for which detailed help is requested.
    """

    detailed_help = {
        4: "\nExample usage for 'Search Protocol':\n\nChoose a protocol to search (dns, eth, http, icmp, smb2, tls): dns",
        10: "\nExample usage for 'Look For Beacons':\n\nEnter the IPv4 address you wish to look for patterns to determine beacons: 10.5.28.8\nEnter the interval frequency (in seconds): 30",
        14: '\nExample usage for "Search For Domain in DNS":\n\nEnter the domain you want to search for here in double quotes: ".onion"\nEnter the domain you want to search for here in double quotes: "wtfismyip.com"',
        18: "\nExample usage for 'Use Any Display Filter':\n\nEnter a valid display filter: nbns\nExpand the packet layers? (Y/N): n\nView all packets? (Y/N): y\nSpecify custom fields? (Y/N): y\nEnter one or more custom field options (comma-separated): nbns.name",
        19: "\nExample usage for 'Search For Valid Tshark Display Filters':\n\nEnter the protocol (e.g., 'dns'): nbns",
        20: "\nExample usage for 'View Statistics':\n\nWhat type of statistics do you want to view? (conv/hosts/srt/tree): : tree\nWhich protocol would you like to see tree statistics for? (dns/ip_hosts/http/http_req/http_srv/plen/ptype): dns",
        21: "\nExample usage for 'Lookup DCERPC Service Method Abuse Info':\n\nEnter the service (e.g., samr, drsuapi, netlogon, lsarpc, srvsvc): lsarpc\nPlease enter an operation number: 76",
    }

    if option and option in detailed_help:
        print(detailed_help[option])

    else:

        while True:
            general_help = f"""
            TigerShark CLI Application - Help Guide
            -----------------------------------
    
            This application provides a range of options for analyzing PCAP files using TShark.
    
            Menu Options:
            
            1. {Color.UNDERLINE}Get PCAP Info{Color.END}: Displays basic information about the specified PCAP file.
            2. {Color.UNDERLINE}Get Protocol Hierarchy Statistics{Color.END}: Shows statistics of protocol distribution.
            3. {Color.UNDERLINE}Get Expert Info{Color.END}: Retrieves expert information from the PCAP analysis.
            4. {Color.UNDERLINE}Search Protocol{Color.END}: Allows searching specific protocols. {Color.LIGHTRED}- Example usage available{Color.END}
            5. {Color.UNDERLINE}Enumerate Hostnames{Color.END}: Lists all hostnames identified in the PCAP file.
            6. {Color.UNDERLINE}Enumerate Users{Color.END}: Enumerates all users found within the PCAP analysis.
            7. {Color.UNDERLINE}Follow TCP Stream{Color.END}: Follows the TCP stream in the PCAP file.
            8. {Color.UNDERLINE}Follow HTTP Stream{Color.END}: Allows for following the HTTP stream in the PCAP file.
            9. {Color.UNDERLINE}Show Packets{Color.END}: Displays packets in the PCAP file.
            10. {Color.UNDERLINE}Look For Beacons{Color.END}: Searches for beacon frames in the PCAP file. {Color.LIGHTRED}- Example usage available{Color.END}
            11. {Color.UNDERLINE}Analyze Web Traffic{Color.END}: Analyzes web traffic found in the PCAP file.
            12. {Color.UNDERLINE}Get WHOIS Data{Color.END}: Retrieves WHOIS data for IPs found in the PCAP.
            13. {Color.UNDERLINE}Find TCP Stream Index In Frame{Color.END}: Finds and displays the TCP stream index in a specified frame.
            14. {Color.UNDERLINE}Search For Domain in DNS{Color.END}: Searches for a specific domain in DNS traffic. {Color.LIGHTRED}- Example usage available{Color.END}
            15. {Color.UNDERLINE}Look For Failed Connection Attempts{Color.END}: Identifies failed connection attempts in the PCAP file.
            16. {Color.UNDERLINE}Get User Agents{Color.END}: Extracts and displays user agent strings from web traffic.
            17. {Color.UNDERLINE}Detect Signs Of ARP Poisoning{Color.END}: Checks for signs of ARP poisoning attacks.
            18. {Color.UNDERLINE}Use Any Display Filter{Color.END}: Allows the use of any TShark display filter on the PCAP file. {Color.LIGHTRED}- Example usage available{Color.END}
            19. {Color.UNDERLINE}Search For Valid Tshark Display Filters{Color.END}: Helps find valid TShark display filters. {Color.LIGHTRED}- Example usage available{Color.END}
            20. {Color.UNDERLINE}View Statistics{Color.END}: Provides various statistics from the PCAP analysis. {Color.LIGHTRED}- Example usage available{Color.END}
            21. {Color.UNDERLINE}Lookup DCERPC Service Method Abuse Info{Color.END}: Looks up information related to DCERPC service method abuse. {Color.LIGHTRED}- Example usage available{Color.END}
            23. {Color.UNDERLINE}Clear Screen{Color.END}: Clears the CLI screen.
            24. {Color.UNDERLINE}Quit{Color.END}: Exits the application.
    
            {Color.BOLD}Enter the number of an option to see detailed usage (e.g., '4' for 'Search Protocol'), or type 'exit' to quit the help menu:{Color.END}
            """

            print(general_help)
            user_input = input("Option number for detailed help or 'exit' to quit: ").strip().lower()

            if user_input == 'exit':
                print("Exiting help menu.")
                break

            try:
                option = int(user_input)
                if option in detailed_help:
                    print(detailed_help[option])
                    input("\nPress Enter to return to the main menu...")  # Wait for user to read details
                else:
                    print("No detailed help available for this option.")

            except ValueError:
                print("Invalid input. Please enter a valid option number or 'exit'.")


if __name__ == '__main__':
    show_help()
