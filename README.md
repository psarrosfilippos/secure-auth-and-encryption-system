
# Secure Authentication and File Encryption System

This project is a secure, multi-layered Python application that demonstrates:
- Safe credential handling through salted MD5 hashing
- AES encryption/decryption for protecting sensitive data
- Digital signatures with ECDSA for file integrity verification

Ideal for learning cryptography basics and secure authentication mechanisms.





## Features

- **Secure Password Storage** using salted MD5 hashing  
- **Credential Management** with file-based storage  
- **File Encryption & Decryption** using AES (OFB mode)  
- **Digital Signature Generation** using ECDSA (Elliptic Curve Digital Signature Algorithm)  
- **Signature Verification** to ensure file authenticity  
- **Public/Private Key Handling** with key export in PEM format  
- **User Login Verification** against stored hashed credentials  
- **Basic Integrity & Security Logic** applied in every step  
- **Educational Purpose**: Designed as a learning project for applied cryptography concepts

## How to use

**1. Run the Program**

Simply execute the Python script:

    python filename.py

**2. User Registration**

- Enter a username and password when prompted.
- The password is salted and hashed using MD5.
- Credentials are stored in a file named credentials.txt. 

**3. Encryption and Signing**

- After registration, the credentials file is encrypted using AES (OFB mode) with a random 256-bit key.
- A digital signature is generated for each encrypted file using ECDSA.

**4. Login and Verification**

- Enter your username and password to log in.

- The encrypted credentials are decrypted only after verifying the signature.
- The program checks if your input matches the stored (hashed) credentials.

**5. Security Notes**

- The encryption key is generated per session (for educational purposes).
- Digital signature verification ensures the integrity and authenticity of encrypted files.
- All intermediate decrypted files are removed after use to preserve confidentiality.
## Examples

**Registering Users**

When the script starts, you'll be prompted to register users:

    Enter your username: alice  
    Enter your password: ****  
    Enter your username: bob  
    Enter your password: ****  
    Enter your username: charlie  
    Enter your password: ****  

This stores their salted + hashed passwords into credentials.txt, then encrypts and signs the file for each user:

    alice_encrypted_credentials.txt  
    alice_encrypted_credentials.txt.sig  
    ...

**Logging In as a User**

    Enter your username for login (or 'q' to quit): alice  
    Enter your password for login: ****

If the file exists and the signature is valid, it shows:

    "Signature is valid.Login successful!"

If anything is tampered with or the password is wrong:

    "Signature verification failed. Cannot proceed with decryption and login.  
    Invalid username or password. Please try again."

**File Outputs**

- credentials.txt: Stores all credentials (hashed & salted)

- *_encrypted_credentials.txt: AES-encrypted credentials per user

- *.sig: Digital signature of the encrypted file

- public_key.pem: Public key used for signature verification

 **Sample credentials.txt content**

    alice,3fbc2891e08e6b85fbc52d43ad49e2b6,afc91a0e1d22341f8c1d01c40bc2df18  
    bob,e99a18c428cb38d5f260853678922e03,b7e23ec29af22b0b4e41da31e868d572  
    charlie,5f4dcc3b5aa765d61d8327deb882cf99,c4ca4238a0b923820dcc509a6f75849b  

Each line represents:
username, hashed_password, salt
Note: Passwords are hashed with MD5(password + salt).



## Security Considerations

- **MD5 is insecure:** Although used here for educational purposes, MD5 is considered cryptographically broken and unsuitable for secure applications. In production systems, stronger algorithms like bcrypt, Argon2, or SHA-256 (with proper salting and stretching) should be used.

- **Hardcoded Key:** The encryption key is generated at runtime and not securely stored or derived from a password. In real systems, key derivation functions (e.g., PBKDF2, scrypt) should be used and secrets should be managed using secure vaults or hardware modules.

- **No Authentication for Encrypted Files:** AES in OFB mode provides confidentiality but not integrity. An authenticated encryption mode like AES-GCM or a MAC (e.g., HMAC) should be added to prevent tampering.

- **Single Credentials File:** All users share the same credentials file. This is acceptable for demonstration but would be insecure and inefficient in a multi-user production environment.

- **No Brute-force Protection:** There is no limit on login attempts or delay mechanism. This makes the system vulnerable to brute-force and dictionary attacks.

- **File Signature Verification:** While the digital signature ensures the authenticity of encrypted files, the user's password itself is still verified using a weak hash (MD5), reducing overall trust in the system.

**Note:** This project was developed as an educational prototype to demonstrate core cryptographic operations. It is not intended for real-world deployment without significant security improvements.
## Acknowledgements

Developed during my 3rd year of university as part of a security-focused coursework project. The goal was to explore applied cryptography techniques including secure credential storage, symmetric encryption, and digital signatures.
Special thanks to my university instructors for providing the foundational knowledge in cryptography and secure systems that inspired this project.


## Authors

Filippos Psarros

informatics and telecommunications Student

GitHub: psarrosfilippos

[README.md](https://github.com/user-attachments/files/21339615/README.md)
