import json
import secrets
import pyperclip
from cryptography.fernet import Fernet, InvalidToken
from ascii_art import start_up
import os


class password_manager:
    def __init__(self):
        self.key = None
        self.master_password = None
        self.password_file = None
        self.password_dict = {}
        self.entry_id_counter = 1

    def create_key(self, path):
        self.key_file_path = path  # Store the key file path
        self.key = Fernet.generate_key()
        self.master_password = input("Enter master password for this key: ")
        with open(path, 'wb') as f:
            f.write(self.key)
        self.encrypt_and_save_master_password(path)

    def encrypt_and_save_master_password(self, path):
        encrypted_master_password = Fernet(self.key).encrypt(
            self.master_password.encode()).decode()
        with open(f"{path}.master", 'w') as f:
            json.dump({"master_password": encrypted_master_password}, f)

    def load_key(self, path):
        self.key_file_path = path  # Store the key file path
        try:
            with open(path, 'rb') as f:
                self.key = f.read()
        except FileNotFoundError:
            print("Invalid key file name. Please check the path and try again.")
            return
        self.master_password = self.get_master_password(path)
        if self.master_password is None:
            return
        entered_password = input(
            "Enter master password for this key: ")
        if entered_password != self.master_password:
            print("Incorrect master password. Access denied.")
            self.key = None
        else:
            print("Master password verified. Key loaded successfully.")

    def get_master_password(self, path):
        try:
            with open(f"{path}.master", 'r') as f:
                master_data = json.load(f)
                return Fernet(self.key).decrypt(master_data['master_password'].encode()).decode()
        except FileNotFoundError:
            print("Master password file not found.")
            return None
        except InvalidToken:
            print("Incorrect master password. Access denied.")
            return None

    def create_password_file(self, path, initial_values=None):
        if self.key is None:
            print(
                "You need to load an existing key or create a new one before creating a password file.")
            return

        self.password_file = path

        if initial_values is not None:
            for key, values in initial_values.items():
                self.add_password(
                    key, values["username"], values["password"])

        # Create the password file
        with open(path, 'w') as f:
            pass

    def load_password_file(self, path):
        try:
            with open(path, 'r') as f:
                for line in f:
                    site, username, encrypted = line.split(":")
                    try:
                        decrypted_password = Fernet(
                            self.key).decrypt(encrypted.encode()).decode()
                        self.password_dict[self.entry_id_counter] = {
                            "site": site, "username": username, "password": decrypted_password}
                        self.entry_id_counter += 1  # Increment the entry ID counter
                    except InvalidToken:
                        print(
                            "This key isn't for this file. Please check the key and try again.")
                        self.password_file = None
                        self.password_dict = {}
                        self.entry_id_counter = 1  # Reset the entry ID counter
                        break
        except FileNotFoundError:
            print(
                "Invalid password file name. Please check the path and try again.")
            return

    def add_password(self, site, username, password):
        if self.password_file is None:
            print("You need to create a password file before adding passwords.")
            return

        self.password_dict[self.entry_id_counter] = {
            "site": site, "username": username, "password": password}
        self.entry_id_counter += 1  # Increment the entry ID counter

        if self.key is not None:
            if self.password_file is not None:
                with open(self.password_file, 'a+') as f:
                    encrypted = Fernet(self.key).encrypt(password.encode())
                    f.write(f"{site}:{username}:{encrypted.decode()}\n")

    def delete_password(self, entry_id):
        if entry_id in self.password_dict:
            del self.password_dict[entry_id]
            print(f"Entry with ID {entry_id} deleted successfully.")
        else:
            print(f"No entry found with ID {entry_id}.")

    def edit_password(self, entry_id, site=None, username=None, password=None):
        if entry_id in self.password_dict:
            if site:
                self.password_dict[entry_id]["site"] = site
            if username:
                self.password_dict[entry_id]["username"] = username
            if password:
                self.password_dict[entry_id]["password"] = password
            print(f"Entry with ID {entry_id} edited successfully.")
        else:
            print(
                f"No entry found with ID {entry_id}. Returning to main menu.")
            return False
        return True

    def get_all_passwords(self):
        return self.password_dict

    def delete_all_entries(self):
        entered_password = input(
            "Enter master password to delete all entries and associated files: ")
        if entered_password != self.master_password:
            print("Incorrect master password. Access denied.")
            return

        confirm = input(
            "Are you sure? This action cannot be undone. (yes/no): ")
        if confirm.lower() == "yes":
            if self.password_file:
                os.remove(self.password_file)
            if hasattr(self, 'key_file_path') and self.key_file_path:
                os.remove(self.key_file_path)  # Use the stored key file path
            master_key_file = f"{self.key_file_path}.master"
            if os.path.exists(master_key_file):
                os.remove(master_key_file)
            self.__init__()  # Reset password manager object
            print("All entries and associated files have been deleted successfully.")

    def generate_password(self):
        # Generate a random password with 20 characters
        return ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*") for _ in range(20))

    def copy_password(self, entry_id):
        if entry_id in self.password_dict:
            password = self.password_dict[entry_id]["password"]
            pyperclip.copy(password)
            print(f"Password for entry with ID {entry_id} copied to clipboard.")
        else:
            print(f"No entry found with ID {entry_id}.")


# Table for prettier output
def print_table(headers, data):
    max_widths = [len(header) for header in headers]
    for row in data:
        for i, value in enumerate(row):
            if isinstance(value, int):          # Check if value is an integer
                value_length = len(str(value))  # Convert integer to string and get length
            else:
                value_length = len(value)
            max_widths[i] = max(max_widths[i], value_length)

    # Headers for print table
    header_line = " | ".join(
        f"{header:<{max_widths[i]}}" for i, header in enumerate(headers))
    print(header_line)
    print("-" * len(header_line))

    # Print data
    for row in data:
        row_line = " | ".join(
            f"{value:<{max_widths[i]}}" for i, value in enumerate(row))
        print(row_line + '\n')


def save_password_file(password_manager):
    if password_manager.password_file:
        with open(password_manager.password_file, 'w') as f:
            for entry_id, credentials in password_manager.password_dict.items():
                encrypted = Fernet(
                    password_manager.key).encrypt(credentials["password"].encode()).decode()
                f.write(
                    f"{credentials['site']}:{credentials['username']}:{encrypted}\n")



def print_menu():
    start_up()
    print(""" What do you want to do?
    1. Create a new key (save as .key)
    2. Load an existing key (specify name including file extension)
    3. Create a new password file
    4. Load existing password file
    a. Add an entry
    v. View passwords & entries
    d. Delete an entry
    e. Edit an entry
    n. Delete all entries and associated files
    g. Generate a password
    c. Copy a password to clipboard
    m. Show this menu
    q. quit
""")


def main():
    password = {}
    pm = password_manager()
    start_up()
    print_menu()  # Print the menu initially
    done = False
    while not done:
        choice = input('Enter your choice ("m" for menu): ')
        if choice == '1':
            path = input('Enter key name (ending in .key): ')
            pm.create_key(path)
        elif choice == '2':
            path = input('Enter key name (ending in .key): ')
            pm.load_key(path)
        elif choice == '3':
            path = input('Enter password file name: ')
            pm.create_password_file(path)
            print('File created successfully')
        elif choice == '4':
            path = input('Enter password file name: ')
            pm.load_password_file(path)
            print('File loaded successfully')
        elif choice == 'a':
            site = input('Enter the site: ')
            username = input('Username: ')
            password = input('Password: ')
            pm.add_password(site, username, password)
        elif choice == 'v':
            passwords = pm.get_all_passwords()
            if passwords:
                print("All passwords:")
                print_table(["ID    ", "Website               ",
                            "Username                 ", "Password             "],
                           [[entry_id, credentials['site'], credentials['username'], credentials['password']] for entry_id, credentials in passwords.items()])
            else:
                print("No passwords stored.")
        elif choice == 'd':
            entry_id = int(input('Enter the ID of the password to delete: '))
            pm.delete_password(entry_id)
        elif choice == 'e':
            entry_id = int(
                input('Enter the ID of the password to edit: '))
            site = input(
                'Enter the site (leave blank to keep current): ')
            username = input(
                'Enter the username (leave blank to keep current): ')
            password = input(
                'Enter the password (leave blank to keep current): ')
            if not pm.edit_password(entry_id, site, username, password):
                continue  # Return to main menu if entry doesn't exist
        elif choice == 'n':
            pm.delete_all_entries()
        elif choice == 'g':  # Generate a password
            generated_password = pm.generate_password()
            print(f"Generated password: {generated_password}")
            pyperclip.copy(generated_password)  # Copy the generated password to clipboard
            print("Generated password copied to clipboard.")
            # List password entries
            passwords = pm.get_all_passwords()
            if passwords:
                print("All passwords:")
                print_table(["ID    ", "Website               ", "Username                 ", "Password             "], 
                            [[entry_id, credentials['site'], credentials['username'], credentials['password']] for entry_id, credentials in passwords.items()])
                while True:
                    entry_id_input = input("Enter the ID of the password you want to replace with the generated password (or 'b' to go back): ")
                    if entry_id_input.lower() == 'b':
                        break  # Go back to main menu
                    try:
                        entry_id = int(entry_id_input)
                        if entry_id in passwords:
                            pm.edit_password(entry_id, password=generated_password)
                            break
                        else:
                            print(f"No password found with ID {entry_id}. Please try again.")
                    except ValueError:
                        print("Invalid input. Please enter a valid ID or 'b' to go back.")
            else:
                print("No passwords stored.")

        elif choice == 'c':  # Copy a password to clipboard
            entry_id = int(
                input('Enter the ID of the password to copy: '))
            pm.copy_password(entry_id)
        elif choice == 'm':  # Show menu again
            print_menu()
        elif choice == 'q':
            save_password_file(pm)
            done = True
            print('Goodbye!')
        else:
            print('Invalid choice')

    # Save the password file before exiting
    save_password_file(pm)


if __name__ == "__main__":
    main()
