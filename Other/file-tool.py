import argparse
import os
from cryptography.fernet import Fernet


def generate_key(key_file="filekey.key"):
    """Generate a new Fernet key and save it to a file if it doesn't exist."""
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        print(f"[+] Key generated and saved to {key_file}")
    else:
        print(f"[i] Key file {key_file} already exists.")


def load_key(key_file="filekey.key"):
    """Load the Fernet key from a file."""
    with open(key_file, "rb") as f:
        return f.read()


def encrypt_file(filename, key):
    """Encrypt a file using the given key."""
    fernet = Fernet(key)
    with open(filename, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(filename, "wb") as f:
        f.write(encrypted)
    print(f"[+] File {filename} encrypted.")


def decrypt_file(filename, key):
    """Decrypt a file using the given key."""
    fernet = Fernet(key)
    with open(filename, "rb") as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    with open(filename, "wb") as f:
        f.write(decrypted)
    print(f"[+] File {filename} decrypted.")


def main():
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt files with Fernet symmetric encryption")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-key
    parser_gen = subparsers.add_parser("generate-key", help="Generate and save a new key")
    parser_gen.add_argument("-k", "--key-file", default="filekey.key", help="Path to key file (default: filekey.key)")

    # encrypt
    parser_enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    parser_enc.add_argument("filename", help="File to encrypt")
    parser_enc.add_argument("-k", "--key-file", default="filekey.key", help="Path to key file (default: filekey.key)")

    # decrypt
    parser_dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    parser_dec.add_argument("filename", help="File to decrypt")
    parser_dec.add_argument("-k", "--key-file", default="filekey.key", help="Path to key file (default: filekey.key)")

    args = parser.parse_args()

    if args.command == "generate-key":
        generate_key(args.key_file)
    elif args.command == "encrypt":
        key = load_key(args.key_file)
        encrypt_file(args.filename, key)
    elif args.command == "decrypt":
        key = load_key(args.key_file)
        decrypt_file(args.filename, key)


if __name__ == "__main__":
    main()
