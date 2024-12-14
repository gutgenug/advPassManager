import os
import json
import base64
import time
import threading
from doctest import master

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Helper to generate a random salt
def generate_salt(length=16):
    return os.urandom(length)

# Derive a key using Scrypt
def derive_key(password, salt, length=32):
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=2**14,  # Cost parameter
        r=8,      # Block size
        p=1       # Parallelization factor
    )
    return kdf.derive(password.encode())

# Encrypt data
def encrypt(data, key):
    iv = os.urandom(16)  # AES uses a 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# Decrypt data
def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data.encode())
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# Save encrypted data to file
def save_to_file(filename, salt, data):
    with open(filename, 'w') as file:
        json.dump({"salt": base64.b64encode(salt).decode(), "passwords": data}, file)

# Load encrypted data from file
def load_from_file(filename):
    if not os.path.exists(filename):  # File doesn't exist
        return None, {}
    try:
        with open(filename, 'r') as file:
            data = json.load(file)  # Load JSON data
            salt = base64.b64decode(data["salt"])
            passwords = data["passwords"]
            return salt, passwords
    except (json.JSONDecodeError, KeyError):  # Handle empty or malformed JSON
        return None, {}
class TimeoutException(Exception):
    """Custom exception to handle timeout."""
    pass

def input_with_timeout(prompt, timeout):
    def interrupt():
        print("\nTimeout! Exiting program.")
        raise TimeoutException()

    # Set a timer to trigger the interrupt
    timer = threading.Timer(timeout, interrupt)
    timer.start()
    try:
        user_input = input(prompt)  # Standard input
        timer.cancel()  # Cancel timer if input is provided
        return user_input
    except TimeoutException:
        exit()  # Exit the program after timeout


# Password Manager
class PasswordManager:
    def __init__(self, filename='passwords.json'):
        self.filename = filename
        self.salt, self.passwords = load_from_file(self.filename)
        self.key = None

    def set_master_password(self, master_password):
        if self.salt is None:
            self.salt = generate_salt()
        self.key = derive_key(master_password, self.salt)
        save_to_file(self.filename, self.salt, self.passwords)
        print("Master password set and saved!")

    def load_master_password(self, master_password):
        if self.salt is None:
            raise ValueError("No master password set!")
        self.key = derive_key(master_password, self.salt)

    def add_password(self, identifier, password):
        if self.key is None:
            raise ValueError("Master password not loaded!")
        encrypted_password = encrypt(password, self.key)
        self.passwords[identifier] = encrypted_password
        save_to_file(self.filename, self.salt, self.passwords)
        print(f"Password for {identifier} added successfully!")

    def get_password(self, identifier):
        if self.key is None:
            raise ValueError("Master password not loaded!")
        encrypted_password = self.passwords.get(identifier)
        if encrypted_password is None:
            raise ValueError("Password not found!")
        return decrypt(encrypted_password, self.key)

    def list_identifiers(self):
        return list(self.passwords.keys())

# Main Program
if __name__ == "__main__":
    manager = PasswordManager()
    timeout_seconds = 10

    print("Welcome to Secure Password Manager!")
    if manager.salt is None:
        print("No master password found. Set one now.")
        master_password = input("Enter a new master password: ").strip()
        manager.set_master_password(master_password)
    else:
        master_password = input("Enter your master password: ").strip()

        if master_password.lower() == "kill":
            if os.path.exists(manager.filename):
                os.remove(manager.filename)
                print("All stored data deleted successfully!")
            else:
                print("No password file found to delete.")
            exit()
        try:
            manager.load_master_password(master_password)
        except ValueError:
            print("Invalid master password!")
            exit()
    try:
        while True:
            print("\nOptions: [add, get, list, exit]")
            option = input_with_timeout("Choose an option: ", timeout_seconds).strip().lower()

            if option == "add":
                identifier = input_with_timeout("Enter identifier (e.g., Gmail): ", timeout_seconds).strip()
                password = input_with_timeout("Enter the password: ", timeout_seconds).strip()
                manager.add_password(identifier, password)
            elif option == "get":
                identifier = input_with_timeout("Enter identifier: ", timeout_seconds).strip()
                try:
                    password = manager.get_password(identifier)
                    print(f"Password for {identifier}: {password}")
                except ValueError as e:
                    print(e)
            elif option == "list":
                identifiers = manager.list_identifiers()
                if identifiers:
                    print("Stored identifiers:", ", ".join(identifiers))
                else:
                    print("No passwords stored yet.")
            elif option == "exit":
                print("Goodbye!")
                break
            else:
                print("Invalid option!")
    except TimeoutException:
        print("No input received. Program terminated.")
