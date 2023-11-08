import subprocess
# Import the 'subprocess' module, which allows you to spawn new processes, connect to their
# input/output/error pipes, and obtain their return codes.

from make_helpers import set_tshark_path
# From the custom module 'make_helpers', import the function 'set_tshark_path'.
# The function 'set_tshark_path' is used to configure the file path for the Tshark application,
# which is a network protocol analyzer.


def valid_display_filters_tshark():
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
        # The specified command is run in a subprocess, captures its standard output, treats it as text, 
        # and raises an error if the subprocess returns a non-zero exit status
        completed_process = subprocess.run(command, stdout=subprocess.PIPE, text=True, check=True)

        # The standard output (stdout) from the completed_process subprocess is split into individual lines, 
        # resulting in a list of lines from the command's output.
        lines = completed_process.stdout.splitlines()
        for line in lines:
            """
            Here's a low-level breakdown of what each part of the code is doing:

            1. output.decode("utf-8"): This assumes output is a bytes-like object (e.g., a byte string) which needs to be decoded into a regular Python string using UTF-8 encoding.
            This is a common operation when dealing with the output of subprocesses or reading binary data from a file that contains text.

            2. .splitlines(): After output has been decoded into a string, splitlines() is called to split the string into a list of strings, where each string is a line from the
            original output. This method splits the string at line boundaries (e.g., the newline character \n).

            3. for line in lines:: This is a loop that iterates over each line in the list lines.

            4. fields = line.split("\t"): Inside the loop, each line is split into a list called fields using the tab character \t as the delimiter.

            5. if len(fields) >= 5 and fields[4] == protocol and "string" in line.lower():: This line is a conditional statement that checks for three conditions before executing
            the block of code that follows:

                len(fields) >= 5: This checks if the number of fields in the line is at least 5, ensuring that the subsequent index access fields[4] does not result in an IndexError.

                fields[4] == protocol: This checks if the fifth field (since Python uses 0-based indexing, fields[4] is the fifth field) equals the variable protocol.

                "string" in line.lower(): This checks if the lowercase version of the line contains the substring "string". This is not case-sensitive since line.lower() converts the
                whole line to lowercase before checking for the substring.

            6. print(f"{fields[2]:<40} : {fields[1]} [{fields[3]}]"): If the condition in the if-statement is true, this line will execute. It prints out formatted text using an f-string,
            which includes:

                fields[2]:<40: This prints the third field in fields and pads it to the left to ensure it takes up at least 40 characters (this is known as left-justifying the string).

                fields[1]: This prints the second field in fields.

                fields[3]: This prints the fourth field in fields, which is enclosed in square brackets.
            """
            fields = line.split("\t")
            if len(fields) >= 5 and fields[4] == protocol and "string" in line.lower():
                print(f"{fields[2]:<40} : {fields[1]} [{fields[3]}]")

    # If the subprocess.run() call raises a subprocess.CalledProcessError exception due to a non-zero 
    # exit status from the executed command, it captures the exception as e and prints an error message 
    # containing the exception details.
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    valid_display_filters_tshark()
