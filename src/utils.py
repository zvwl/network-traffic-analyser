import sys
import termios
import tty
import time
from colorama import Fore, Style

def loading_spinner(text, duration=5):
    spinner = ['-', '\\', '|', '/']
    start_time = time.time()
    i = 0
    while time.time() - start_time < duration:
        sys.stdout.write(f"\r{text} {spinner[i % len(spinner)]}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    sys.stdout.write("\rDone!                                       \n")

def get_keypress():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
        if ch == '\x1b':  # Check if the first byte is an escape character
            ch += sys.stdin.read(2)  # Read two more bytes
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def glowing_text(text, iterations=5):
    for i in range(iterations):
        # Display the text in normal green
        print(Fore.GREEN + text + Style.RESET_ALL, end='\r')
        time.sleep(0.5)
        # Display the text in brighter green
        print(Fore.LIGHTGREEN_EX + text + Style.RESET_ALL, end='\r')
        time.sleep(0.5)
    print()  # Add a newline after the glowing effect is done

def get_duration_input():
    while True:
        try:
            duration = int(input(Fore.GREEN + "Enter capture duration in seconds: " + Style.RESET_ALL))
            if duration > 0:
                return duration
            else:
                print(Fore.RED + "Please enter a positive number." + Style.RESET_ALL)
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter a number." + Style.RESET_ALL)

def get_ip_input():
    while True:
        ip = input(Fore.GREEN + "Enter IP address to filter: " + Style.RESET_ALL)
        if ip:
            return ip
        else:
            print(Fore.RED + "Invalid input. Please enter a valid IP address." + Style.RESET_ALL)

def get_packet_size_range():
    while True:
        try:
            min_size = int(input(Fore.GREEN + "Enter minimum packet size (bytes): " + Style.RESET_ALL))
            max_size = int(input(Fore.GREEN + "Enter maximum packet size (bytes): " + Style.RESET_ALL))
            if min_size > 0 and max_size > min_size:
                return min_size, max_size
            else:
                print(Fore.RED + "Invalid input. Please enter positive numbers with max size greater than min size." + Style.RESET_ALL)
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter numbers." + Style.RESET_ALL)
