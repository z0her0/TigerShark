"""
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
from make_helpers import set_tshark_path


def valid_display_filters_tshark() -> None:
    """
    Repeatedly prompts the user to enter a network protocol and displays valid Tshark display filters 
    associated with that protocol. The function exits when the user inputs 'exit'.

    This function runs Tshark with the "-G fields" argument to retrieve a list of all available display filters.
    It then filters this list to show only those filters related to the user-specified protocol, focusing on 
    filters that contain string fields.

    The user can continuously input protocols to search for their corresponding display filters 
    before choosing to exit the program.
    """
    while True:
        # Prompt the user for the protocol
        protocol = input("Enter the protocol (e.g., 'dns'), or 'exit' to quit: ")
        if protocol.lower() == 'exit':
            break

        tshark = f"{set_tshark_path()[0]}"
        try:
            # Run the tshark command
            command = [tshark, "-G", "fields"]
            with subprocess.Popen(command, stdout=subprocess.PIPE, shell=False) as process:
                output, _ = process.communicate()

            # Process the output
            lines = output.decode("utf-8").splitlines()
            for line in lines:
                fields = line.split("\t")
                if len(fields) >= 5 and fields[4] == protocol and "string" in line.lower():
                    print(f"{fields[2]:<40} : {fields[1]} [{fields[3]}]")

        except subprocess.SubprocessError as e:
            print(f"A subprocess error occurred: {e}")

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        print("\n")


if __name__ == "__main__":
    valid_display_filters_tshark()
