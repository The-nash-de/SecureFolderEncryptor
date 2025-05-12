
import os
import argparse
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import pickle

def generate_key(password, salt, iterations=100000, key_length=32):
    """Generate a secure encryption key using PBKDF2."""
    return PBKDF2(password, salt, dkLen=key_length, count=iterations)

def add_padding(data, block_size=16):
    """Add PKCS#7 padding to the data."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def remove_padding(data):
    """Remove PKCS#7 padding from the data."""
    pad_len = data[-1]
    if pad_len > 16:  # Protect against corrupted or tampered data
        raise ValueError("Invalid padding. Possible wrong password or corrupted file.")
    return data[:-pad_len]

def compute_hmac(key, data):
    """Compute HMAC-SHA256 for integrity verification."""
    return hmac.new(key, data, hashlib.sha256).digest()

def encrypt_file(input_folder, output_file, password):
    """Encrypt all files in a folder and write them to a single output file."""

    if not os.path.exists(input_folder):
        raise FileNotFoundError(f"Input folder '{input_folder}' does not exist.")

    if not os.listdir(input_folder):
        raise ValueError(f"Input folder '{input_folder}' is empty.")

    salt = get_random_bytes(16)
    key = generate_key(password, salt)

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    file_structure = []  

    for root, _, files in os.walk(input_folder):
        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, input_folder)
            with open(filepath, 'rb') as infile:
                data = infile.read()
                file_structure.append((relative_path, data))

    serialized_data = pickle.dumps(file_structure)
    serialized_data = add_padding(serialized_data)

    ciphertext = cipher.encrypt(serialized_data)

    # Berechne HMAC für den verschlüsselten Text
    hmac_key = generate_key(password, salt, key_length=32)  # HMAC-Schlüssel
    mac = compute_hmac(hmac_key, ciphertext)

    with open(output_file, 'wb') as outfile:
        outfile.write(salt)  # 16 Byte
        outfile.write(iv)  # 16 Byte
        outfile.write(mac)  # 32 Byte HMAC
        outfile.write(ciphertext)

    print(f"Encryption completed. Output saved to: {output_file}")

def decrypt_file(input_file, output_folder, password):
    """Decrypt an encrypted file and reconstruct the folder and file structure."""
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file '{input_file}' does not exist.")

    os.makedirs(output_folder, exist_ok=True)

    with open(input_file, 'rb') as infile:
        salt = infile.read(16)
        iv = infile.read(16)
        mac = infile.read(32)  # HMAC einlesen
        ciphertext = infile.read()

    key = generate_key(password, salt)
    hmac_key = generate_key(password, salt, key_length=32)  # HMAC-Schlüssel

    # Überprüfe die Integrität der Datei mit HMAC
    computed_mac = compute_hmac(hmac_key, ciphertext)
    if not hmac.compare_digest(mac, computed_mac):
        raise ValueError("Integrity check failed! File may have been tampered with.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    serialized_data = cipher.decrypt(ciphertext)
    serialized_data = remove_padding(serialized_data)

    file_structure = pickle.loads(serialized_data)

    for relative_path, file_data in file_structure:
        output_path = os.path.join(output_folder, relative_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as outfile:
            outfile.write(file_data)

    print(f"Decryption completed. Files restored to: {output_folder}")

def main():
    parser = argparse.ArgumentParser(description="Cryptographic tool to encrypt or decrypt files.")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt files in a folder")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt an encrypted file")
    parser.add_argument("--input", required=True, type=str, help="Input folder or file")
    parser.add_argument("--output", required=True, type=str, help="Output file or folder")
    parser.add_argument("--password", required=True, type=str, help="Password for encryption/decryption")
    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        print("Error: You cannot use --encrypt and --decrypt at the same time.")
        parser.print_help()
        exit(1)

    try:
        if args.encrypt:
            encrypt_file(args.input, args.output, args.password)
        elif args.decrypt:
            decrypt_file(args.input, args.output, args.password)
        else:
            print("Error: You must specify either --encrypt or --decrypt.")
            parser.print_help()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
