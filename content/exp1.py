import os
import argparse
import pyperclip

def create_file(filename):
    content_folder = "content"
    if not os.path.exists(content_folder):
        os.makedirs(content_folder)
    file_path = os.path.join(content_folder, filename)
    with open(file_path, 'w') as file:
        file.write('Sample text in ' + filename)

def read_file(filename):
    content_folder = "content"
    file_path = os.path.join(content_folder, filename)
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return f"File '{filename}' not found."

def list_files():
    content_folder = "content"
    files = os.listdir(content_folder)
    return '\n'.join(files)

def copy_to_clipboard(text):
    pyperclip.copy(text)

def main():
    parser = argparse.ArgumentParser(description='Command-line tool for file management and copying to clipboard.')
    parser.add_argument('command', choices=['create', 'read', 'copy', 'ls'], help='Command to execute')
    parser.add_argument('filename', nargs='?', help='File name')

    args = parser.parse_args()

    if args.command == 'create':
        create_file(args.filename)
        print(f"File '{args.filename}' created successfully.")
    elif args.command == 'read':
        content = read_file(args.filename)
        print(content)
    elif args.command == 'copy':
        content = read_file(args.filename)
        copy_to_clipboard(content)
        print("File content copied to clipboard.")
    elif args.command == 'ls':
        files_list = list_files()
        print("Files in 'content' directory:")
        print(files_list)

if __name__ == "__main__":
    main()
