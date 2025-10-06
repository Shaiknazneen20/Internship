# file_integrity_checker.py
# Author: CODTECH Internship
# Description: Monitor file integrity by calculating and comparing hash values.

import hashlib
import os

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()

def monitor_file(file_path, stored_hash):
    """Compare the current file hash with the stored hash."""
    current_hash = calculate_hash(file_path)
    if current_hash == stored_hash:
        print("[✔] File integrity is intact.")
    else:
        print("[⚠] File has been modified!")

if __name__ == "__main__":
    file_path = input("Enter the path of the file to monitor: ")

    if not os.path.exists(file_path):
        print("[❌] File not found!")
        exit()

    print("[*] Calculating initial hash...")
    original_hash = calculate_hash(file_path)
    print(f"[HASH SAVED] Original SHA-256: {original_hash}")

    input("\n[!] Modify the file and press ENTER to recheck integrity...\n")
    monitor_file(file_path, original_hash)