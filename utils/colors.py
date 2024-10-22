#!/scrapEnv/bin/python3.11

# Python Script to declare the colors

class Colors:
    """A class to define terminal colors for printing."""
    
    # Reset
    R = '\033[0m'

    # Regular colors
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    ORANGE = '\033[1;32m'

    # Regular text colors
    WHITE = '\033[0;33m'
    PURPLE = '\033[0;34m'
    CYAN = '\033[0;36m'

    # Bold text colors
    BOLD_WHITE = '\033[1;31m'
    BOLD_PURPLE = '\033[1;34m'
    BOLD_CYAN = '\033[1;36m'
