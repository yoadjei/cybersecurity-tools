import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import scapy.all as scapy
import time
import random
import re

# AES Encryption
def encrypt_data(data, key):
    key = hashlib.sha256(key.encode()).digest()  # Generate a 256-bit key
    cipher = AES.new(key, AES.MODE_CBC)  # CBC mode of encryption
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))  # Encrypt the data
    iv = cipher.iv  # Initialization vector
    return iv, ct_bytes

def decrypt_data(iv, ct_bytes, key):
    key = hashlib.sha256(key.encode()).digest()  # Generate the same key for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)  # CBC mode decryption
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt.decode()

# Password Strength Analyzer
def analyze_password_strength(password):
    # Simple regex for a strong password (at least 8 characters, 1 uppercase, 1 number)
    if len(password) >= 8 and re.search(r"[A-Z]", password) and re.search(r"\d", password):
        return True
    else:
        return False

# Network Sniffer for Fraud Detection
def sniff_network():
    print("Starting network sniffing...")
    # Sniffing HTTP traffic on the network to detect unusual transactions
    packets = scapy.sniff(filter="tcp port 80", count=10, timeout=10)  # Listen to HTTP packets
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            print(f"Packet detected from {ip_src} to {ip_dst}")
            # Simple fraud detection: Check for unusual IP addresses (for demo purposes)
            if ip_src not in ["trusted_ip_1", "trusted_ip_2"]:  # Placeholder trusted IPs
                print("Warning: Unusual source IP detected!")

# Simulated Financial Transaction Log for Fraud Detection
def simulate_transaction():
    # A list of dummy transactions (e.g., amount, type, and IP address)
    transactions = [
        {"amount": random.randint(10, 5000), "ip": "192.168.1.2", "type": "transfer"},
        {"amount": random.randint(10, 5000), "ip": "192.168.1.3", "type": "transfer"},
        {"amount": random.randint(10, 5000), "ip": "192.168.1.4", "type": "withdrawal"},
    ]
    selected_transaction = random.choice(transactions)  # Simulate a random transaction
    print(f"Simulated transaction: {selected_transaction}")
    # Fraud detection: Large transaction (for demo purposes)
    if selected_transaction["amount"] > 3000:
        print("Warning: Large transaction detected!")

# Main function that simulates the complete FinSecGuard
def finsecguard():
    # Step 1: Encrypting Financial Data
    financial_data = "Account_Number: 1234567890, Balance: $10000"
    encryption_key = "SecureEncryptionKey"
    iv, encrypted_data = encrypt_data(financial_data, encryption_key)
    print(f"Encrypted Financial Data: {encrypted_data}")

    # Step 2: Decrypting Financial Data
    decrypted_data = decrypt_data(iv, encrypted_data, encryption_key)
    print(f"Decrypted Financial Data: {decrypted_data}")

    # Step 3: Password Strength Analysis
    password = "P@ssw0rd2024"
    is_strong = analyze_password_strength(password)
    print(f"Password Strength: {'Strong' if is_strong else 'Weak'}")

    # Step 4: Simulating Fraud Detection with Network Sniffer
    sniff_network()

    # Step 5: Simulating Transaction Log Analysis
    simulate_transaction()

# Running the FinSecGuard Tool
if __name__ == "__main__":
    finsecguard()