import argparse
import os
from cryptography.fernet import Fernet


def generate_key(key_file="filekey.key"):
    """Generate a new Fernet key and save it as UTF-8 text (base64)."""
    if not os.path.exists(key_file):
        key_bytes = Fernet.generate_key()
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(key_bytes.decode("utf-8"))
        print(f"[+] Key generated and saved to {key_file}")
    else:
        print(f"[i] Key file {key_file} already exists.")


def load_key(key_file="filekey.key"):
    """Load Fernet key from UTF-8 text and return bytes."""
    with open(key_file, "r", encoding="utf-8") as f:
        key_text = f.read().strip()
    return key_text.encode("utf-8")


def encrypt_file(filename, key):
    """
    Read plaintext as binary, encrypt, and write ciphertext as UTF-8 text
    to <filename>_encrypted.
    """
    fernet = Fernet(key)
    with open(filename, "rb") as f:
        plaintext_bytes = f.read()

    encrypted_bytes = fernet.encrypt(plaintext_bytes)

    encrypted_filename = f"{filename}_encrypted"
    with open(encrypted_filename, "w", encoding="utf-8") as f:
        f.write(encrypted_bytes.decode("utf-8"))

    print(f"[+] File {filename} encrypted -> {encrypted_filename} (UTF-8 text)")


def decrypt_file(filename, key):
    """
    Read ciphertext as UTF-8 text, decrypt, and write plaintext as binary
    to a new file with '_decrypted' in the name.
    """
    fernet = Fernet(key)
    with open(filename, "r", encoding="utf-8") as f:
        encrypted_text = f.read()

    decrypted_bytes = fernet.decrypt(encrypted_text.encode("utf-8"))

    if filename.endswith("_encrypted"):
        decrypted_filename = filename.replace("_encrypted", "_decrypted")
    else:
        decrypted_filename = f"{filename}_decrypted"

    with open(decrypted_filename, "wb") as f:
        f.write(decrypted_bytes)

    print(f"[+] File {filename} decrypted -> {decrypted_filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Fernet file crypto: encrypt writes UTF-8 ciphertext; decrypt writes binary plaintext."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-key
    p_gen = subparsers.add_parser("generate-key", help="Generate and save a key (UTF-8 text)")
    p_gen.add_argument("-k", "--key-file", default="filekey.key", help="Key file path (default: filekey.key)")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file (reads binary, writes UTF-8 text)")
    p_enc.add_argument("filename", help="File to encrypt")
    p_enc.add_argument("-k", "--key-file", default="filekey.key", help="Key file path (default: filekey.key)")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt a file (reads UTF-8, writes binary with new name)")
    p_dec.add_argument("filename", help="File to decrypt")
    p_dec.add_argument("-k", "--key-file", default="filekey.key", help="Key file path (default: filekey.key)")

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
