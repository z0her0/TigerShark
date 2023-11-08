# make_colorful.py
import random
# Import the random module to generate random numbers, shuffle sequences randomly, and choose random items.
# This is used to generate different menu option colors each time you use TigerShark

class ColorCustom:
    """Class to represent the text color codes used for terminal output."""

    COLORS = [
        "\033[95m", "\033[96m", "\033[36m", "\033[35m", "\033[34m",
        "\033[94m", "\033[32m", "\033[92m", "\033[93m", "\033[33m",
        "\033[31m", "\033[91m",
        "\033[38;5;208m", "\033[38;5;200m", "\033[38;5;23m",
        "\033[38;5;154m", "\033[38;5;51m", "\033[38;5;92m", "\033[38;5;220m",
        "\033[38;5;54m", "\033[38;5;197m", "\033[38;5;183m",
        "\033[38;5;111m", "\033[38;5;203m", "\033[38;5;230m",
        "\033[38;5;45m", "\033[38;5;120m", "\033[38;5;17m",
        "\033[38;5;207m", "\033[38;5;122m",
    ]

    def __init__(self):
        self.color = random.choice(self.COLORS)
        self.END = "\033[0m"


class Color:
    """Class to represent the text color codes used for terminal output."""

    # Builtin colors
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARKCYAN = "\033[36m"
    MAGENTA = "\033[35m"
    BLUE = "\033[34m"
    LIGHTBLUE = "\033[94m"
    GREEN = "\033[32m"
    LIGHTGREEN = "\033[92m"
    LIGHTYELLOW = "\033[93m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    LIGHTRED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"

    # Custom colors
    ORANGE = "\033[38;5;208m"
    PINK = "\033[38;5;200m"
    TEAL = "\033[38;5;23m"
    GREY = "\033[38;5;240m"
    LIME = "\033[38;5;154m"
    AQUA = "\033[38;5;51m"
    VIOLET = "\033[38;5;92m"
    GOLD = "\033[38;5;220m"
    INDIGO = "\033[38;5;54m"
    ROSE = "\033[38;5;197m"
    LAVENDER = "\033[38;5;183m"
    MAROON = "\033[38;5;88m"
    OLIVE = "\033[38;5;58m"
    SKY_BLUE = "\033[38;5;111m"
    CORAL = "\033[38;5;203m"
    BEIGE = "\033[38;5;230m"
    TURQUOISE = "\033[38;5;45m"
    MINT = "\033[38;5;120m"
    NAVY = "\033[38;5;17m"
    PLUM = "\033[38;5;96m"
    MUSTARD = "\033[38;5;214m"
    CYCLAMEN = "\033[38;5;207m"
    SEAFOAM = "\033[38;5;122m"


# The following block will only be executed if this module is run as the main script.
if __name__ == '__main__':
    # This code will not run when the module is imported.
    pass
