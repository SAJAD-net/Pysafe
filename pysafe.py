#!/usr/bin/env python3

import base64
import getpass
import os
import pathlib
import secrets
import sys
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def generate_salt(size=16):
    """Generate the salt used for key derivation"""
    return secrets.token_bytes(size)


def derive_key(salt, password):
    """Derive the key from the `password` using the passed `salt`"""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def load_salt(path):
    # load salt from pysalt.salt file
    if os.path.exists(f"{path}conf/pysalt.salt"):    
        salt = open(f"{path}conf/pysalt.salt", "rb").read()
    else:
        salt = generate_salt()
        if not os.path.exists(f"{path}conf"):
            os.mkdir(f"{path}conf")
        with open(f"{path}conf/pysalt.salt", "wb") as salt_file:
            salt_file.write(salt)

    return salt


def generate_key(password, path, salt_size=16):
    """
    Generates a key from a `password` and the salt.
    """
    
    # load existing salt
    salt = load_salt(path)
    # sys.exit()
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)

    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)


def encryptor(file, key):
    fkey = Fernet(key)
    
    if "pysalt.salt" in str(file):
        return

    with open(file, "rb") as f:
        # read all file data
        file_data = f.read()

    # encrypt data
    try:
        encrypted_data = fkey.encrypt(file_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        sys.exit()

    print(f"[*] Encrypting {file}")

    # write the encrypted file
    with open(file, "wb") as f:
        f.write(encrypted_data)


def encrypt(path, key):
    """
    Given a path (str) and key (bytes), it encrypts the path and write it
    """
    if os.path.isdir(path):
        """
        if it's a folder, encrypt the entire folder.
        """
        for child in pathlib.Path(path).glob("*"):
            if child.is_file():
                # encrypt the file
                encryptor(child, key)
            elif child.is_dir():
                """
                if it's a folder, encrypt the entire folder by calling this function recursively
                """
                encrypt(child, key)

    elif os.path.isfile(path):
        encryptor(path, key)


def decryptor(file, key):
    fkey = Fernet(key)
    
    if "pysalt.salt" in str(file):
        return

    with open(file, "rb") as f:
        # read all file data
        file_data = f.read()

    # decrypt data
    try:
        decrypted_data = fkey.decrypt(file_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        sys.exit()

    print(f"[*] Decrypting {file}")

    # write the decrypted file
    with open(file, "wb") as f:
        f.write(decrypted_data)


def decrypt(path, key):
    """
    Given a path (str) and key (bytes), it decrypts the path and write it
    """
    if os.path.isdir(path):
        # if it's a folder, decrypt the entire folder (i.e all the containing files)
        for child in pathlib.Path(path).glob("*"):
            if child.is_file():
                # decrypt the file
                decryptor(child, key)
            elif child.is_dir():
                # if it's a folder, decrypt the entire folder by calling this function recursively
                decrypt(child, key)

    elif os.path.isfile(path):
        decryptor(path, key)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PySafe File Encryptor")
    parser.add_argument("-p", "--path", help="Path to encrypt/decrypt")
    parser.add_argument("-s", "--salt-size", required=False,
        help="If this is set, a new salt with the passed size is generated", type=int)
    parser.add_argument("-e", "--encrypt", action="store_true",
        help="Whether to encrypt the path, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",
        help="Whether to decrypt the path, only -e or -d can be specified.")

    args = parser.parse_args()
    path = args.path
    if path.split("/")[-1] != '':
        path+="/"

    try:
        if args.encrypt:
            password = getpass.getpass("[+] Enter the password for encryption: ")
        elif args.decrypt:
            password = getpass.getpass("[+] Enter the password you used for encryption: ")

        if args.salt_size:
            key = generate_key(password, path, salt_size=args.salt_size)
        else:
            key = generate_key(password, path)

    except Exception:
        parser.print_help()
        sys.exit()

    encrypt_ = args.encrypt
    decrypt_ = args.decrypt

    WAR_MESSAGE = "[!] Please specify whether you want to encrypt the path or decrypt it."
    if encrypt_ and decrypt_:
        raise TypeError(WAR_MESSAGE)
    elif encrypt_:
        encrypt(path, key)
        print("\n[+] Encryption successfully completed!")
    elif decrypt_:
        decrypt(path, key)
        print("\n[+] Decryption successfully completed!")
    else:
        raise TypeError(WAR_MESSAGE)
