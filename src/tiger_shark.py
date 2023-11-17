"""  # pylint: disable=line-too-long
This module defines a colorful, music-themed command-line interface (CLI) for interacting with TShark,
a network protocol analyzer. It provides various options for analyzing PCAP files and displaying information.
"""

import os
import ctypes
import sys
from typing import Dict, Callable, Union

from rich.console import Console
from rich.table import Table
from rich.text import Text
from prompt_toolkit import prompt
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.application.current import get_app

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


# pylint: disable=line-too-long
def print_menu_options(menu_options: dict, colors: dict, selected_option: int = None) -> None:
    # def print_menu_options(menu_options: dict, colors: dict) -> None:
    """
    Prints the menu options in a formatted table.
    
    Args:
        :param menu_options: A dictionary containing the menu options and their descriptions.
        :param colors: A dictionary containing the color settings for each menu option.
        :param selected_option: 
    """
    console = Console()
    table = Table(show_header=True, header_style="bold green")
    # print(r"    ٩(●̮̮̃•̃)=/̵͇̿̿/'̿̿ ̿̿                              ̿̿ ̿̿ ̿̿\̵͇̿̿\=(•̃●̮̮̃)۶")
    table.add_column("🎧♪┏(°.°)┛🎼", style="bold cyan", justify="left")
    table.add_column("🎼┏(°.°)┛♪🎧", style="bold violet", justify="right")
    # table.add_column("🎼┏(°.°)┛♪🎧", style="dim", justify="right")
    for key, value in menu_options.items():
        desc = value["description"]
        color = colors[key]
        style = f"rgb({color[0]},{color[1]},{color[2]})"
        if selected_option and key == str(selected_option):
            # Highlight the selected option
            style += " bold underline" 
        # text = Text(f"{key}. {desc}", style=style)
        text = Text(f"{desc}", style=style)
        table.add_row(key, text)
    console.print(table)
    console.print("\nUse the arrow keys to navigate and enter to select an option.", style="bold yellow")


def main() -> None:
    ask_user_input: str = input("Enter path to PCAP: ")

    print(make_banner_art.mascot)

    # Dictionary to store menu options and their corresponding actions
    menu_options: MenuOptionsType = {
        "1": {
            "description": "Get PCAP Info",
            "action": lambda: print(
                f"{Color.LIGHTBLUE}Capture File Information{Color.END}:\n"
                f"{TShark(pcap_file=ask_user_input).pcap_info()}")
        },
        "2": {
            "description": "Get Protocol Hierarchy Statistics",
            "action": lambda: print(TShark(pcap_file=ask_user_input).iophs())
        },
        "3": {
            "description": "Get Expert Info",
            "action": lambda: print(
                f"{Color.LIGHTYELLOW}Expert Info{Color.END}:\n{TShark(pcap_file=ask_user_input).expert_chat()}")
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
                f"{Color.MAGENTA}Follow TCP Stream{Color.END}:\n{TShark(pcap_file=ask_user_input).tcp_stream()}")
        },
        "8": {
            "description": "Follow HTTP Stream",
            "action": lambda: print(
                f"{Color.MAGENTA}Follow HTTP Stream{Color.END}:\n{TShark(pcap_file=ask_user_input).http_stream()}")
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
            "action": lambda: TShark(pcap_file=ask_user_input).whois_ip()
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
            "description": "Use Any Display Filter",
            "action": lambda: print(
                f"{Color.MAGENTA}Use Any Display Filter{Color.END}:\n"
                f"{TShark(pcap_file=ask_user_input).display_filter()}")
        },
        "19": {
            "description": "Search For Valid Tshark Display Filters",
            "action": lambda: valid_display_filters_tshark()
        },
        "20": {
            "description": "View Statistics",
            "action": lambda: print(f"{TShark(pcap_file=ask_user_input).statistics()}")
        },
        "21": {
            "description": "Lookup DCERPC Service Method Abuse Info",
            "action": lambda: print(f"{TShark(pcap_file=ask_user_input).get_dcerpc_abuse_info()}")
        },
        "22": {
            "description": "Help Menu",
            "action": lambda: show_help()
        },
        "23": {
            "description": "Clear Screen",
            "action": lambda: (clear_screen(), None)[1]
        },
        "24": {
            "description": "Quit",
            "action": lambda: sys.exit("Exit program.")
        }
    }

    # Define key bindings for arrow key navigation
    bindings = KeyBindings()

    # Use a list for mutability in closure
    selected_option = [1] 

    @bindings.add('up')
    def _(event):
        selected_option[0] = max(1, selected_option[0] - 1)
        # Refresh the menu
        get_app().exit() 

    @bindings.add('down')
    def _(event):
        selected_option[0] = min(len(menu_options), selected_option[0] + 1)
        # Refresh the menu
        get_app().exit() 

    @bindings.add('enter')
    def _(event):
        get_app().exit(result=selected_option[0])

    while True:
        clear_screen()
        print("")
        print(f"{Color.LIGHTYELLOW}((*´_●｀☆ﾟ+.•°•.•°• 🎧♪┏(°.°)┛🎼 Wh47 w0u1d y0u 1!k3 70 d0 ? 🎼┏(°.°)┛♪🎧 •°•.•°•.+ﾟ☆´●_｀*)){Color.END}")
        print(f'{Color.MAROON}_____________________________________________________________________________________'
              f'_______{Color.END}')

        print_menu_options(menu_options, menu_colors, selected_option[0])

        action_key = str(prompt('> Use arrow keys (◦′ᆺ‵◦) ♬° ✧❥✧¸.•*¨*✧♡✧ ✧♡✧*¨*•.❥ to navigate and enter to select an option: ',
                                key_bindings=bindings, refresh_interval=0.5))

        if action_key in menu_options:
            clear_screen()
            action = menu_options[action_key]["action"]
            if callable(action):
                action()
            else:
                print("Error: The action is not callable.")
            wait_for_menu()
        else:
            print(f"{Color.RED}Invalid selection. Please choose a number between 1 and 24.{Color.END}")


# Dictionary of menu colors for each menu option
menu_colors: Dict[str, tuple] = {str(i): ColorRandomRGB.random_color() for i in range(1, 25)}

# Check if this script is the main script (it is) and call the main function
if __name__ == '__main__':
    main()
