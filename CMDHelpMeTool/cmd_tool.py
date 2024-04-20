import argparse
import pyperclip
from .experiments import *  # Import all variables from experiments.py

def copy_variable_to_clipboard(variable):
    try:
        pyperclip.copy(variable)
        print("File content copied to clipboard.")
    except pyperclip.PyperclipException:
        print("Failed to copy to clipboard.")
        print(variable)

def main():
    parser = argparse.ArgumentParser(description='Command-line tool for copying variable content to clipboard.')
    parser.add_argument('command', choices=['copy_experiment'], help='Command to execute')
    parser.add_argument('variable_name', help='Name of the variable to copy')

    args = parser.parse_args()

    if args.command == 'copy_experiment':
        variable = globals().get(args.variable_name)
        if variable is not None:
            copy_variable_to_clipboard(variable)
        else:
            print(f"Variable '{args.variable_name}' not found.")

if __name__ == "__main__":
    main()
