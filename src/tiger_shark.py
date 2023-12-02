"""  # pylint: disable=line-too-long
This module provides an interactive menu-driven interface for analyzing PCAP files using TShark, a network protocol analyzer.
It allows users to perform various operations such as getting PCAP information, viewing protocol statistics, following streams,
enumerating hosts and users, and more. Rich library is used to create a colorful terminal interface, enhancing user experience.

Functions:
    clear_screen(): Clears the console screen based on the operating system.
    wait_for_menu(): Waits for the user to press Enter to continue.
    print_menu_options(menu_options, colors): Prints the available menu options in a table format.
    main(): The main function that initiates the menu loop and processes user input to perform actions.

The program uses a command-line interface and expects the user to interact by entering the path to a PCAP file and selecting
options from the presented menu. The TShark class methods are invoked based on the user's choices to analyze the PCAP data
and provide results back to the user.
"""

import os
import ctypes
import sys
from typing import Dict, Callable, Union

from rich.console import Console
from rich.table import Table
from rich.text import Text

import make_banner_art
from make_help import show_help
from make_tshark_class import TShark
from search_tshark_filters import valid_display_filters_tshark
from make_colorful import Color, ColorRandomRGB


# Type alias for the action in menu options
ActionType = Callable[[], None]

# Define a dictionary type for menu options
MenuOptionsType = Dict[str, Dict[str, Union[str, ActionType]]]


def clear_screen() -> None:
    """
    Clears the console screen using alternative methods, instead of using shell commands.
    """
    # For Windows
    if os.name == 'nt':
        # We can use the ctypes library to call the Win32 API for clearing the console.
        ctypes.windll.kernel32.SetConsoleCursorPosition(ctypes.windll.kernel32.GetStdHandle(-11), 0)
    else:
        # We can use an escape sequence to clear the terminal
        print("\033c", end="")


def wait_for_menu() -> None:
    """
    Waits for the user to press Enter to display the menu.
    """
    input("\nPress Enter to display the menu... ")


def print_menu_options(menu_options: dict, colors: dict) -> None:
    """
    Prints the menu options in a formatted table.

    Args:
        menu_options (dict): A dictionary containing the menu options and their descriptions.
        colors (dict): A dictionary containing the color settings for each menu option.
    """
    console = Console()
    table = Table(show_header=True)
    print(r"    ٩(●̮̮̃•̃)=/̵͇̿̿/'̿̿ ̿̿                              ̿̿ ̿̿ ̿̿\̵͇̿̿\=(•̃●̮̮̃)۶")
    table.add_column("🎧♪┏(°.°)┛🎼", style="bold cyan", justify="left")
    table.add_column("🎼┏(°.°)┛♪🎧", style="bold magenta", justify="right")
    keys = list(menu_options.keys())
    for i in range(0, len(keys), 2):
        key1 = keys[i]
        desc1 = menu_options[key1]["description"]
        color1 = colors[key1]
        text1 = Text(f"{key1}. {desc1}", style=f"rgb({color1[0]},{color1[1]},{color1[2]})")
        if i + 1 < len(keys):
            key2 = keys[i + 1]
            desc2 = menu_options[key2]["description"]
            color2 = colors[key2]
            text2 = Text(f"{key2}. {desc2}", style=f"rgb({color2[0]},{color2[1]},{color2[2]})")
        else:
            text2 = Text("")
        table.add_row(text1, text2)
    console.print(table)


def main() -> None:
    """
    Main function to drive the program which interacts with the user to perform operations on PCAP files.
    
    The function presents a menu to the user, allowing them to choose from various actions related to PCAP analysis.
    These actions include getting PCAP information, viewing protocol hierarchy statistics, expert info, searching
    protocols, enumerating hostnames and users, following TCP/HTTP streams, displaying packets, and more.
    
    Each menu option is associated with an action that when chosen, calls a function from the TShark class with the
    provided PCAP file path.
    """
    ask_user_input: str = input("Enter path to PCAP: ")

    # Dictionary to store menu options and their corresponding actions
    menu_options: MenuOptionsType = {
        "1": {
            "description": "Get PCAP Info",
            "action": lambda: print(
                f"\n{Color.LIGHTBLUE}Capture File Information{Color.END}:\n"
                f"{TShark(pcap_file=ask_user_input).pcap_info()}")
        },
        "2": {
            "description": "Get Protocol Hierarchy Statistics",
            "action": lambda: print(TShark(pcap_file=ask_user_input).iophs())
        },
        "3": {
            "description": "Get Expert Info",
            "action": lambda: print(
                f"\n{Color.LIGHTYELLOW}Expert Info{Color.END}:\n{TShark(pcap_file=ask_user_input).expert_chat()}")
        },
        "4": {
            "description": "Search Protocol",
            "action": lambda: TShark(pcap_file=ask_user_input).process_and_display_verbose_results()
        },
        "5": {
            "description": "Enumerate Hostnames",
            "action": lambda: print(
                TShark(pcap_file=ask_user_input).display_results(*TShark(pcap_file=ask_user_input).host_enum()))
        },
        "6": {
            "description": "Enumerate Users",
            "action": lambda: print(
                TShark(pcap_file=ask_user_input).display_results(*TShark(pcap_file=ask_user_input).user_enum()))
        },
        "7": {
            "description": "Follow TCP Stream",
            "action": lambda: print(
                f"{TShark(pcap_file=ask_user_input).tcp_stream()}")
        },
        "8": {
            "description": "Follow HTTP Stream",
            "action": lambda: print(
                f"{TShark(pcap_file=ask_user_input).http_stream()}")
        },
        "9": {
            "description": "Show Packets",
            "action": lambda: print(
                f"{Color.MAGENTA}Show Packets{Color.END}:\n{TShark(pcap_file=ask_user_input).show_packets()}")
        },
        "10": {
            "description": "Look For Beacons",
            "action": lambda: print(
                f"{Color.DARKCYAN}Look For Beacons{Color.END}:\n{TShark(pcap_file=ask_user_input).find_beacons()}")
        },
        "11": {
            "description": "Analyze Web Traffic",
            "action": lambda: print(
                f"{Color.LIGHTYELLOW}Analyze Web Traffic{Color.END}:\n{TShark(pcap_file=ask_user_input).web_basic()}")
        },
        "12": {
            "description": "Get WHOIS Data",
            "action": lambda: f"\n{TShark(pcap_file=ask_user_input).whois_ip()}"
        },
        "13": {
            "description": "Find TCP Stream Index In Frame",
            "action": lambda: print(
                f"{Color.YELLOW}Find TCP Stream From Frame{Color.END}:\n"
                f"{TShark(pcap_file=ask_user_input).viewframe_getstream()}")
        },
        "14": {
            "description": "Search For Domain in DNS",
            "action": lambda: print(
                f"{Color.CYAN}Search For Domain Name{Color.END}:\n{TShark(pcap_file=ask_user_input).dns_hunt()}")
        },
        "15": {
            "description": "Look For Failed Connection Attempts",
            "action": lambda: print(
                f"{Color.DARKCYAN}Look For Failed Connection Attempts{Color.END}:\n"
                f"{TShark(pcap_file=ask_user_input).failed_connections()}")
        },
        "16": {
            "description": "Get User Agents",
            "action": lambda: TShark(pcap_file=ask_user_input).process_and_display_user_agents()
        },
        "17": {
            "description": "Detect Signs Of ARP Poisoning",
            "action": lambda: print(
                f"{Color.CYAN}Detect Signs Of ARP Poisoning{Color.END}:\n"
                f"{TShark(pcap_file=ask_user_input).arp_thunt()}")
        },
        "18": {
            "description": "Detect Spambot Activity",
            "action": lambda: print(f"{TShark(pcap_file=ask_user_input).spambot()}")
        },
        "19": {
            "description": "Use Any Display Filter",
            "action": lambda: print(
                f"{Color.MAGENTA}Use Any Display Filter{Color.END}:\n"
                f"{TShark(pcap_file=ask_user_input).display_filter()}")
        },
        "20": {
            "description": "Search For Valid Tshark Display Filters",
            "action": lambda: valid_display_filters_tshark()
        },
        "21": {
            "description": "View Statistics",
            "action": lambda: print(f"{TShark(pcap_file=ask_user_input).statistics()}")
        },
        "22": {
            "description": "Follow Flows",
            "action": lambda: print(f"{TShark(pcap_file=ask_user_input).flow_any()}")
        },
        "23": {
            "description": "Lookup DCERPC Service Method Abuse Info",
            "action": lambda: print(f"{TShark(pcap_file=ask_user_input).get_dcerpc_abuse_info()}")
        },
        "24": {
            "description": "Help Menu",
            "action": lambda: show_help()
        },
        "25": {
            "description": "Clear Screen",
            "action": lambda: (clear_screen(), None)[1]
        },
        "26": {
            "description": "Quit",
            "action": lambda: sys.exit("Exit program.")
        }
    }
    
    clear_screen()
    print(make_banner_art.mascot)

    while True:
        wait_for_menu()
        clear_screen()
        print("")
        print(f"{Color.LIGHTYELLOW}((*´_●｀☆ﾟ+.•°•.•°• 🎧♪┏(°.°)┛🎼 Wh47 w0u1d y0u 1!k3 70 d0 ? 🎼┏(°.°)┛♪🎧 •°•.•°•.+ﾟ☆´●_｀*)){Color.END}")
        print(f'{Color.MAROON}_____________________________________________________________________________________'
              f'_______{Color.END}')

        print_menu_options(menu_options, menu_colors)

        print("")
        user_choice = input('> ENTER NUMBER HERE (◦′ᆺ‵◦) ♬° ✧❥✧¸.•*¨*✧♡✧ ✧♡✧*¨*•.❥ : ')

        if user_choice in menu_options:
            clear_screen()
            print("\n")

            action = menu_options[user_choice]["action"]

            if callable(action):
                action()
            else:
                print("Error: The action is not callable.")

        else:
            print(f"{Color.RED}Invalid selection. Please choose a number between 1 and 26.{Color.END}")


# Dictionary of menu colors for each menu option
menu_colors: Dict[str, tuple] = {str(i): ColorRandomRGB.random_color() for i in range(1, 27)}

# Check if this script is the main script (it is) and call the main function
if __name__ == '__main__':
    main()
