"""
This module provides utility functions and classes for working with TShark,
a network protocol analyzer. It includes functionality to set the path for
TShark based on the operating system, validate various types of user input
(such as IP addresses, intervals, and numeric digits), and process the
output of TShark commands.

Key components include:
- `set_tshark_path()`: Determines the correct path for TShark and Capinfos executables.
- `is_valid_ipv4_address()`, `is_valid_interval()`, `is_valid_digit()`: Functions to validate user input.
- `get_input_opnum()`, `input_prompt()`: Functions to prompt and validate user input.
- `process_output()`: Processes the raw output from TShark commands, with special handling for HTTP and DNS protocols.

These utilities are designed to assist in automating and simplifying the usage of TShark in network analysis tasks.
"""
import ipaddress
import platform
from typing import Callable, Optional, Tuple


def set_tshark_path() -> Tuple[str, str]:
    """
    Set the paths for tshark and capinfos based on the host operating system.
    This function determines the host operating system (macOS or Linux) and sets the appropriate paths
    for the tshark and capinfos executables based on that information.
    Returns:
        Tuple[str, str]: A tuple containing the paths for tshark and capinfos.
    Raises:
        ValueError: If the host operating system is not supported.
    """
    # Get the host operating system
    os_system = platform.system()

    # Initialize variables to store the paths
    capinfo = ''
    tshark = ''

    # Check if the host operating system is macOS (Darwin)
    if os_system == 'Darwin':
        
        # Set the paths for macOS
        tshark += '/Applications/Wireshark.app/Contents/MacOS/tshark'
        capinfo += '/Applications/Wireshark.app/Contents/MacOS/capinfos'

    # Check if the host operating system is Linux
    elif os_system == 'Linux':
        
        # Set the paths for Linux
        tshark += '/usr/bin/tshark'
        capinfo += '/usr/bin/capinfos'

    # Handle unsupported operating systems
    else:
        raise ValueError(f"Unsupported operating system: {os_system}")

    # Return the paths for tshark and capinfos as a tuple
    return tshark, capinfo


def is_valid_ipv4_address(ip: str) -> bool:
    """
    Check if the given string is a valid IPv4 address.
    Args:
        ip (str): The input string to check for IPv4 validity.
    Returns:
        bool: True if the input string is a valid IPv4 address, False otherwise.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_interval(freq: str) -> bool:
    """
    Check if the given string represents a valid numeric interval.
    Args:
        freq (str): The input string to check for numeric validity.
    Returns:
        bool: True if the input string is a valid numeric interval, False otherwise.
    """
    return freq.isnumeric()


def is_valid_digit(input_dig: str) -> bool:
    """
    Check if the given string represents a valid numeric digit.
    Args:
        input_dig (str): The input string to check for numeric validity.
    Returns:
        bool: True if the input string is a valid numeric digit, False otherwise.
    """
    return input_dig.isnumeric()


def get_input_opnum() -> int:
    """
    Prompt the user to enter an operation number repeatedly until valid input is received.
    The function expects the user to enter a numeric value. If the user enters a non-numeric value,
    the function will print an error message and prompt the user again. When the user enters a valid
    numeric value, the function will return it as an integer.
    Returns:
        int: The user input converted to an integer.
    """
    while True:
        user_input = input("Please enter an operation number: ")
        if is_valid_digit(user_input):
            return int(user_input)
        print("Invalid input. Please enter a numeric value.")


def input_prompt(prompt: str, validator: Optional[Callable[[str], bool]] = None) -> str:
    """
    Prompt the user for input and validate it using a custom validator function.
    Args:
        prompt (str): The prompt to display to the user.
        validator (Callable[[str], bool], optional): A function that takes a string input and returns True if
        the input is valid, or False otherwise. Default is None.
    Returns:
        str: The user's input if it passes validation.
    """
    while True:
        user_input = input(prompt)
        if validator is not None and not validator(user_input):
            print("Invalid input. Please try again.")
            continue
        return user_input


# The following block will only be executed if this module is run as the main script.
if __name__ == '__main__':
    pass
