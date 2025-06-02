from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_bin_file(input_file, output_file):
    # Read the input file
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Generate random key and IV
    key = get_random_bytes(32)  # 256 bits for SHA-256
    iv = get_random_bytes(16)   # 128 bits for AES block size
    
    # Create SHA-256 hash of the key
    from Crypto.Hash import SHA256
    hash_obj = SHA256.new()
    hash_obj.update(key)
    derived_key = hash_obj.digest()[:16]  # Take first 128 bits for AES-128
    
    # Create AES cipher in CBC mode
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    
    # Pad the data
    padding_length = AES.block_size - (len(data) % AES.block_size)
    padded_data = data + bytes([padding_length] * padding_length)
    
    # Encrypt the data
    encrypted_data = cipher.encrypt(padded_data)
    
    # Write IV and encrypted data to output file
    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(encrypted_data)
    
    print(f"Encryption complete. Output written to {output_file}")
    print(f"Key (hex): {key.hex()}")
    print(f"IV (hex): {iv.hex()}")

if __name__ == "__main__":
    input_file = "nt205.bin"
    output_file = "enc_nt205.bin"
    encrypt_bin_file(input_file, output_file) 