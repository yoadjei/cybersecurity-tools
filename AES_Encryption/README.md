# Text Encryption with AES (Advanced Encryption Standard)

This tool uses AES in CBC (Cipher Block Chaining) mode to securely encrypt and decrypt text data. It is ideal for anyone wanting to learn about or apply AES encryption in their projects.

## Features
- Secure Key and IV Generation: Generates a unique 256-bit key and 16-byte IV for each session.
- Padding: Ensures text is properly padded for encryption using PKCS7.
- CBC Mode Encryption: Protects data from unauthorized access with AES CBC.

## How to Use
1. Clone the repository.
2. Install the required libraries.
3. Run encrypt.py or decrypt.py as needed.

## Technical Details
- AES in CBC Mode: Each encryption operation is unique, even for the same text.
- Python Requirements: Python 3.7+, with the cryptography library.

## Disclaimer
This tool is for educational purposes only. Be responsible when handling sensitive data.
