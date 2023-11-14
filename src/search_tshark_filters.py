"""  # pylint: disable=line-too-long
This module provides functionality to interact with TShark, a network protocol analyzer,
to retrieve and display valid display filters based on user-specified protocols. It is
designed to assist users in identifying relevant TShark filters for their network analysis
tasks, particularly focusing on filters that contain string fields.

The module utilizes the 'subprocess' library to execute TShark commands and processes
the output to extract and print the desired filter information. Users are prompted to
input a protocol name, and the module then lists all the valid display filters associated
with that protocol, emphasizing those that contain string fields.

Key Functions:
- valid_display_filters_tshark: Prompts the user for a protocol and prints valid TShark
  display filters related to that protocol, specifically targeting filters with string fields.

The module is intended to be run as a standalone script, where it executes the
valid_display_filters_tshark function on launch, providing a user-friendly interface
for querying TShark display filters.

Example Usage:
Run the script directly, and when prompted, enter a protocol name (e.g., 'dns') to see
a list of related TShark display filters.
"""

import subprocess
# Import the 'subprocess' module, which allows you to spawn new processes, connect to their
# input/output/error pipes, and obtain their return codes.

from make_helpers import set_tshark_path
# From the custom module 'make_helpers', import the function 'set_tshark_path'.
# The function 'set_tshark_path' is used to configure the file path for the Tshark application,
# which is a network protocol analyzer.


def valid_display_filters_tshark() -> None:
    """
    Prompts the user for a protocol and prints out valid tshark display filters
    associated with that protocol, specifically those that contain string fields.

    The function first retrieves the path to the tshark executable using the
    `set_tshark_path()` function. It then runs tshark with the "-G fields"
    argument to get a list of all display filters. The output is processed to
    find and print display filters related to the user-specified protocol.
    """
    # Prompt the user for the protocol
    protocol = input("Enter the protocol (e.g., 'dns'): ")
    tshark = f"{set_tshark_path()[0]}"
    try:
        # Run the tshark command
        command = [
            tshark,
            "-G",
            "fields",
        ]
        with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
            output, _ = process.communicate()

        # Process the output
        lines = output.decode("utf-8").splitlines()
        for line in lines:
            fields = line.split("\t")
            if len(fields) >= 5 and fields[4] == protocol and "string" in line.lower():
                print(f"{fields[2]:<40} : {fields[1]} [{fields[3]}]")

    except subprocess.SubprocessError as e:
        print(f"A subprocess error occurred: {e}")

    except Exception as e:  # pylint: disable=broad-except
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    valid_display_filters_tshark()
