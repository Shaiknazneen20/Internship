# aes_encryption_tool.py
# Author: CODTECH Internship
# Description: Encrypt and decrypt files using AES-256

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, "rb") as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(file_path + ".enc", "wb") as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

    print("[✔] File encrypted successfully!")

def decrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    output_file = file_path.replace(".enc", "_decrypted")
    with open(output_file, "wb") as f:
        f.write(data)

    print("[✔] File decrypted successfully!")

if __name__ == "__main__":
    print("=== AES-256 File Encryption Tool ===")
    key = get_random_bytes(32)  # 256-bit key
    choice = input("Encrypt or Decrypt? (e/d): ").lower()

    file_path = input("Enter file path: ")
    if not os.path.exists(file_path):
        print("[❌] File not found!")
        exit()

    if choice == "e":
        encrypt_file(file_path, key)
    elif choice == "d":
        decrypt_file(file_path, key)
    else:
        print("[❌] Invalid option!")