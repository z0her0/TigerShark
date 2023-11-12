# make_colorful.py
import random
# Import the random module to generate random numbers, shuffle sequences randomly, and choose random items.
# This is used to generate different menu option colors each time you use TigerShark


class ColorRGB:
    """Class to represent RGB color values equivalent to the ANSI color codes."""

    # Builtin colors (approximations)
    PURPLE = (128, 0, 128)  # Equivalent to ANSI 'Purple'
    CYAN = (0, 255, 255)    # Equivalent to ANSI 'Cyan'
    DARKCYAN = (0, 139, 139)  # Equivalent to ANSI 'Dark Cyan'
    MAGENTA = (255, 0, 255)  # Equivalent to ANSI 'Magenta'
    BLUE = (0, 0, 255)      # Equivalent to ANSI 'Blue'
    LIGHTBLUE = (173, 216, 230)  # Equivalent to ANSI 'Light Blue'
    GREEN = (0, 128, 0)     # Equivalent to ANSI 'Green'
    LIGHTGREEN = (144, 238, 144)  # Equivalent to ANSI 'Light Green'
    LIGHTYELLOW = (255, 255, 224)  # Equivalent to ANSI 'Light Yellow'
    YELLOW = (255, 255, 0)  # Equivalent to ANSI 'Yellow'
    RED = (255, 0, 0)       # Equivalent to ANSI 'Red'
    LIGHTRED = (255, 204, 203)  # Equivalent to ANSI 'Light Red'

    # Custom colors (based on xterm-256color palette approximations)
    ORANGE = (255, 135, 0)
    PINK = (255, 105, 180)
    TEAL = (0, 128, 128)
    GREY = (190, 190, 190)
    LIME = (50, 205, 50)
    AQUA = (0, 255, 255)
    VIOLET = (238, 130, 238)
    GOLD = (255, 215, 0)
    INDIGO = (75, 0, 130)
    ROSE = (255, 0, 127)
    LAVENDER = (230, 230, 250)
    MAROON = (128, 0, 0)
    OLIVE = (128, 128, 0)
    SKY_BLUE = (135, 206, 235)
    CORAL = (255, 127, 80)
    BEIGE = (245, 245, 220)
    TURQUOISE = (64, 224, 208)
    MINT = (189, 252, 201)
    NAVY = (0, 0, 128)
    PLUM = (221, 160, 221)
    MUSTARD = (255, 219, 88)
    CYCLAMEN = (255, 113, 113)
    SEAFOAM = (159, 226, 191)


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
