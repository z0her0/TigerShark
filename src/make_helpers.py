import ipaddress
import platform
from typing import Callable, Optional, Tuple
from collections import Counter


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
        else:
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


def process_output(raw_output: str, protocol: str) -> list[tuple[str, int]]:
    """
    Process the given raw output based on the specified protocol and return
    the count of occurrences for each line.
    If the protocol is 'http' or 'dns', the URLs in the output are defanged by
    replacing 'http://' with 'hxxp://' and '.' with '[.]'. This is achieved by
    iterating over each line and applying the replacements. The function then
    counts the occurrences of each defanged line. For other protocols, it counts
    the occurrences of each line as is.
    Args:
    raw_output (str): A string containing the raw output to be processed.
    protocol (str): The protocol type based on which the processing varies.
                    Currently, only 'http' is handled specifically.
    Returns:
    list[tuple[str, int]]: A list of tuples, each containing a line and its
                           count of occurrences, sorted by frequency in
                           descending order.
    """
    # Split the output into lines
    lines = raw_output.strip().split('\n')

    # Remove leading and trailing whitespace and tabs from each line
    cleaned_lines = [line.strip().replace('\t', '') for line in lines if line.strip()]

    # Defang URLs if http or dns
    if protocol in ('http', 'dns'):
        defanged = []
        for line in cleaned_lines:
            # Apply replace to each string in the list
            defanged.append(line.replace("http://", "hxxp://").replace("https://", "hxxp://").replace(".", "[.]"))

        # Count occurrences of each cleaned line and return the counts as a string
        sorted_counts = Counter(defanged).most_common()
        return sorted_counts
    else:
        # Count occurrences of each cleaned line
        sorted_counts = Counter(cleaned_lines).most_common()

        # Return the counts as a string
        return sorted_counts


# The following block will only be executed if this module is run as the main script.
if __name__ == '__main__':
    # This code will not run when the module is imported.
    pass
