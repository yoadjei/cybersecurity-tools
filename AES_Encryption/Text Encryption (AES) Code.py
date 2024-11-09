
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_text_aes(plaintext, key):
    # Generate a random 16-byte IV (Initialization Vector) for security
    iv = os.urandom(16)
    # Set up the AES cipher in CBC mode with the provided key and generated IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to be a multiple of 128 bits (16 bytes), which AES requires
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(plaintext.encode()) + padder.finalize()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    # Return both the IV and ciphertext, since the IV is needed for decryption
    return iv + ciphertext

# Example of usage
key = os.urandom(32)  # Generate a secure random 256-bit key
plaintext = "Hello, this is a secure message!"
encrypted_text = encrypt_text_aes(plaintext, key)
print("Encrypted text:", encrypted_text)