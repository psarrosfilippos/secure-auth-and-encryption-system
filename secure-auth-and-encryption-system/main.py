# FILIPPOS PSARROS
# 2628

import hashlib  # Import hashlib library for cryptographic hashing
import os  # Import os library for system operations
import getpass  # Import getpass library for password hiding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Import cryptographic libraries
from cryptography.hazmat.backends import default_backend  # Import default_backend
from cryptography.hazmat.primitives.asymmetric import ec  # Import ECDSA cryptography
from cryptography.hazmat.primitives import serialization  # Import serialization library
from cryptography.hazmat.primitives import hashes  # Import hashes library for hashing

# Function to hash a password using salt
def hash_password(password, salt):
    salted_password = password + salt
    hashed_password = hashlib.md5(salted_password.encode()).hexdigest()
    return hashed_password

# Function to save credentials to a file
def save_credentials(username, hashed_password, salt, filename='credentials.txt'):
    with open(filename, 'a') as file:
        file.write(f"{username},{hashed_password},{salt}\n")

# Function to encrypt a file
def encrypt_file(input_filename, output_filename, key):
    with open(input_filename, 'rb') as f:
        plaintext = f.read()

    iv = os.urandom(16)  # Generate random IV

    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())  # Create cipher object
    encryptor = cipher.encryptor()  # Initialize encryptor

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()  # Encrypt content

    with open(output_filename, 'wb') as f:
        f.write(iv + ciphertext)  # Write encrypted content to output file

# Function to decrypt a file
def decrypt_file(input_filename, output_filename, key):
    with open(input_filename, 'rb') as f:
        iv = f.read(16)  # Read IV from file
        ciphertext = f.read()  # Read encrypted content from file

    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())  # Create cipher object
    decryptor = cipher.decryptor()  # Initialize decryptor

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt content

    with open(output_filename, 'wb') as f:
        f.write(plaintext)  # Write decrypted content to output file

# Function to sign a file
def sign_file(filename, private_key):
    with open(filename, 'rb') as f:
        data = f.read()

    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

    with open(f'{filename}.sig', 'wb') as f:
        f.write(signature)

# Function to verify a file's signature
def verify_signature(filename, signature_filename, public_key):
    with open(filename, 'rb') as f:
        data = f.read()

    with open(signature_filename, 'rb') as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False

# Main program execution
def main():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())  # Generate private key
    public_key = private_key.public_key()  # Get public key

    users_credentials = []  # Initialize list for user credentials
    users = 3  # Number of users

    for _ in range(users):
        username = input("Enter your username: ")  # Username input
        password = getpass.getpass("Enter your password: ")  # Password input
        salt = os.urandom(16).hex()  # Generate salt
        hashed_password = hash_password(password, salt)  # Hash password
        users_credentials.append((username, hashed_password, salt))  # Add to credentials list

    credentials_filename = 'credentials.txt'  # Credentials filename

    # Save credentials to file
    for username, hashed_password, salt in users_credentials:
        save_credentials(username, hashed_password, salt, credentials_filename)

    key = os.urandom(32)  # Generate encryption key

    # Encrypt credentials and sign them
    for username, hashed_password, _ in users_credentials:
        input_filename = credentials_filename
        encrypted_filename = f"{username}_encrypted_credentials.txt"
        encrypt_file(input_filename, encrypted_filename, key)
        sign_file(encrypted_filename, private_key)

    # Save public key to file
    with open('public_key.pem', 'wb') as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    # User login and credential verification
    while True:
        username = input("Enter your username for login (or 'q' to quit): ")
        if username == 'q':
            break

        password = getpass.getpass("Enter your password for login: ")

        encrypted_filename = f"{username}_encrypted_credentials.txt"
        signature_filename = f'{encrypted_filename}.sig'

        if not os.path.exists(encrypted_filename):
            print("User not found. Please try again.")
            continue

        with open('public_key.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        if verify_signature(encrypted_filename, signature_filename, public_key):
            print("Signature is valid.")
            decrypted_filename = f"{username}_decrypted_credentials.txt"
            decrypt_file(encrypted_filename, decrypted_filename, key)

            found = False
            with open(decrypted_filename, 'r') as f:
                for line in f:
                    saved_username, stored_hashed_password, stored_salt = line.strip().split(',')
                    if saved_username == username:
                        login_hashed_password = hash_password(password, stored_salt)
                        if stored_hashed_password == login_hashed_password:
                            print("Login successful!")
                            found = True
                            break

            # Re-encrypt the file after login attempt
            encrypt_file(decrypted_filename, encrypted_filename, key)
            sign_file(encrypted_filename, private_key)
            os.remove(decrypted_filename)

            if found:
                break
        else:
            print("Signature verification failed. Cannot proceed with decryption and login.")

        if not found:
            print("Invalid username or password. Please try again.")

if __name__ == "__main__":
    main()
