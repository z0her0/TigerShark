import subprocess
# The subprocess module allows you to spawn new processes, connect to their input/output/error pipes, and obtain
# their return codes.

import sys
# This module provides access to some variables used or maintained by the interpreter and to functions that interact
# strongly with the interpreter.

import make_banner_art
# Custom module for creating ASCII art for banners.

from typing import (
    Dict,       # Dict: A container datatype that stores key-value pairs.
    Callable,   # Callable: A type hint for variables that are callable.
    Union       # Union: A type hint that a variable can be one of several types
)

from make_tshark_class import TShark
# Custom TShark class to provide an interface to the tshark network protocol analyzer.

from search_tshark_filters import valid_display_filters_tshark
# Function related to validating display filters for TShark from a custom module.

from make_colorful import Color, ColorCustom
# Classes from a custom module for adding color to text or console outputs for aesthetic or organizational purposes.

# Type alias for the action in menu options
ActionType = Callable[[], None]

# Define a dictionary type for menu options
MenuOptionsType = Dict[str, Dict[str, Union[str, ActionType]]]


def main() -> None:
    """
    This is the main function that orchestrates the display and interaction of a colorful, music-themed
    command-line interface (CLI) menu.

    Upon calling, it:
    - Prints a styled banner with different colors.
    - Continuously displays a series of menu options with a music-themed prompt until the user exits.
    - Allows the user to select an option by entering the corresponding number.
    - Calls the appropriate function associated with the chosen option.
    - Handles invalid selections with an error message.
    """
    print('')
    print(rf"{Color.LIGHTRED}                           ___ _  _, __, __,  _, _,_  _, __, _,_{Color.END}")
    print(rf"{Color.LIGHTYELLOW}                            |  | / _ |_  |_) (_  |_| /_\ |_) |_/{Color.END}")
    print(rf"{Color.LIGHTBLUE}                            |  | \ / |   | \ , ) | | | | | \ | \{Color.END}")
    print(rf"{Color.LIGHTGREEN}                            ~  ~  ~  ~~~ ~ ~  ~  ~ ~ ~ ~ ~ ~ ~ ~{Color.END}")
    print(rf"{Color.MAGENTA}                                  '·.¸¸.·♩♪♫', '♫♪♩·.¸¸.·'{Color.END}")

    print(make_banner_art.banner)

    while True:
        print(rf"{Color.LIGHTYELLOW}((*´_●｀☆ﾟ+.•°•.•°• 🎧♪┏(°.°)┛🎼 Wh47 w0u1d y0u 1!k3 70 d0 ? 🎼┏(°.°)┛♪🎧 •°•.•°•.+ﾟ☆´●_｀*)){Color.END}")
        print(f'{Color.MAROON}____________________________________________________________________________________________{Color.END}')

        for key, option in menu_options.items():
            print(f"{menu_colors[key].color}{key}. {option['description']}{menu_colors[key].END}")

        print(f"")

        user_choice = input('> ENTER NUMBER HERE (◦′ᆺ‵◦) ♬° ✧❥✧¸.•*¨*✧♡✧ ✧♡✧*¨*•.❥ : ')

        if user_choice in menu_options:
            menu_options[user_choice]["action"]()
        else:
            print(f"{Color.RED}Invalid selection. Please choose a number between 1 and 22.{Color.END}")


# Define a dictionary to store menu options and their corresponding actions
menu_options: MenuOptionsType = {
    "1": {
        "description": "Get PCAP Info",
        "action": lambda: print(f"{Color.LIGHTBLUE}Capture File Information{Color.END}:\n{TShark(pcap_file=ask_user_input).pcap_info()}")
    },
    "2": {
        "description": "Get Protocol Hierarchy Statistics",
        "action": lambda: print(TShark(pcap_file=ask_user_input).iophs())
    },
    "3": {
        "description": "Get Expert Info",
        "action": lambda: print(f"{Color.LIGHTYELLOW}Expert Info{Color.END}:\n{TShark(pcap_file=ask_user_input).expert_chat()}")
    },
    "4": {
        "description": "Search Protocol",
        "action": lambda: print(f"{Color.LIGHTGREEN}Search Protocol{Color.END}\n{TShark(pcap_file=ask_user_input).read_verbose()}")
    },
    "5": {
        "description": "Enumerate Streams",
        "action": lambda: print(f"{Color.LIGHTGREEN}Custom Output{Color.END}:\n{TShark(pcap_file=ask_user_input).enum_streams()}")
    },
    "6": {
        "description": "Follow TCP Stream",
        "action": lambda: print(f"{Color.MAGENTA}Follow TCP Stream{Color.END}:\n{TShark(pcap_file=ask_user_input).tcp_stream()}")
    },
    "7": {
        "description": "Follow HTTP Stream",
        "action": lambda: print(f"{Color.MAGENTA}Follow HTTP Stream{Color.END}:\n{TShark(pcap_file=ask_user_input).http_stream()}")
    },
    "8": {
        "description": "Show Packets",
        "action": lambda: print(f"{Color.MAGENTA}Show Packets{Color.END}:\n{TShark(pcap_file=ask_user_input).show_packets()}")
    },
    "9": {
        "description": "Look For Beacons",
        "action": lambda: print(f"{Color.DARKCYAN}Look For Beacons{Color.END}:\n{TShark(pcap_file=ask_user_input).find_beacons()}")
    },
    "10": {
        "description": "Analyze Web Traffic",
        "action": lambda: print(f"{Color.LIGHTYELLOW}Analyze Web Traffic{Color.END}:\n{TShark(pcap_file=ask_user_input).web_basic()}")
    },
    "11": {
        "description": "Get WHOIS Data",
        "action": lambda: print(f"{TShark(pcap_file=ask_user_input).whois_ip()}")
    },
    "12": {
        "description": "Find TCP Stream Index In Frame",
        "action": lambda: print(f"{Color.YELLOW}Find TCP Stream From Frame{Color.END}:\n{TShark(pcap_file=ask_user_input).viewframe_getstream()}")
    },
    "13": {
        "description": "Search For Specific Domain in DNS",
        "action": lambda: print(f"{Color.CYAN}Search For Domain Name{Color.END}:\n{TShark(pcap_file=ask_user_input).dns_hunt()}")
    },
    "14": {
        "description": "Look For Failed Connection Attempts",
        "action": lambda: print(f"{Color.DARKCYAN}Look For Failed Connection Attempts{Color.END}:\n{TShark(pcap_file=ask_user_input).failed_connections()}")
    },
    "15": {
        "description": "Get User Agents",
        "action": lambda: print(f"{Color.LIGHTYELLOW}Get User Agents{Color.END}:\n{TShark(pcap_file=ask_user_input).user_agent()}")
    },
    "16": {
        "description": "Detect Signs Of ARP Poisoning",
        "action": lambda: print(f"{Color.CYAN}Detect Signs Of ARP Poisoning{Color.END}:\n{TShark(pcap_file=ask_user_input).arp_thunt()}")
    },
    "17": {
        "description": "Use Any Display Filter",
        "action": lambda: print(f"{Color.MAGENTA}Use Any Display Filter{Color.END}:\n{TShark(pcap_file=ask_user_input).display_filter()}")
    },
    "18": {
        "description": "Search For Valid Tshark Display Filters",
        "action": lambda: print(f"{valid_display_filters_tshark()}")
    },
    "19": {
        "description": "View Statistics",
        "action": lambda: print(f"{TShark(pcap_file=ask_user_input).statistics()}")
    },
    "20": {
        "description": "Lookup DCERPC Service Method Abuse Info",
        "action": lambda: print(f"{TShark(pcap_file=ask_user_input).get_dcerpc_abuse_info()}")
    },
    "21": {
        "description": "Clear Screen",
        "action": lambda: subprocess.call('clear')
    },
    "22": {
        "description": "Quit",
        "action": lambda: sys.exit("Exit program.")
    }
}

# Define the dictionary of menu colors for each menu option
menu_colors: Dict[str, ColorCustom] = {str(i): ColorCustom() for i in range(1, 23)}

# Check if this script is the main script (it is) and call the main function
if __name__ == '__main__':
    ask_user_input = input("Enter path to PCAP: ")
    main()
