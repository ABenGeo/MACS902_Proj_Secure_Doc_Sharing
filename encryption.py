import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def encrypt_file(input_file, encrypted_file):
    file_data = Path(input_file).read_bytes() # Reads the original document
    aes_key = AESGCM.generate_key(bit_length=256) # Generates a random 256-bit AES key
    nonce = os.urandom(12) # Generate a random 12-byte nonce
    # Encrypt the document
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    Path(encrypted_file).write_bytes(nonce + ciphertext) # Saves the nonce followed by the ciphertext and authentication tag
    return aes_key

def decrypt_file(encrypted_file, decrypted_file, aes_key):
    encrypted_data = Path(encrypted_file).read_bytes() # Reads the encrypted document
    nonce = encrypted_data[:12] # Extracts the nonce (first 12 bytes)
    ciphertext = encrypted_data[12:] # Extracts the ciphertext and authentication tag
    # Decrypt and verify the document
    aesgcm = AESGCM(aes_key)
    file_data = aesgcm.decrypt(nonce, ciphertext, None)
    Path(decrypted_file).write_bytes(file_data) # Saves the recovered document
    return "Document decrypted successfully!"

def encrypt_uploaded_file(file_data, encrypted_file):
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        file_data,
        None
    )
    encrypted_path = Path(encrypted_file)
    encrypted_path.parent.mkdir(parents=True, exist_ok=True)
    encrypted_path.write_bytes(nonce + ciphertext)
    return aes_key

if __name__ == "__main__":
    aes_key = encrypt_file(
        "confidential_document.txt",
        "encrypted_document.bin"
    )
    print("1. Document encrypted successfully!")
    message = decrypt_file(
        "encrypted_document.bin",
        "decrypted_document.txt",
        aes_key
    )
    print("2.", message)
    # Compare original and decrypted documents
    original = Path("confidential_document.txt").read_bytes()
    recovered = Path("decrypted_document.txt").read_bytes()
    print("3. Document recovery verified:", original == recovered)
    # Testing decryption with a wrong AES key
    wrong_key = AESGCM.generate_key(bit_length=256)
    try:
        decrypt_file(
            "encrypted_document.bin",
            "wrong_decryption.txt",
            wrong_key
        )
        print("4. Incorrect key test: Failed")
    except InvalidTag:
        print("4. Incorrect key test: Passed - decryption rejected!")
    # Testing detection of modified encrypted data
    encrypted_data = bytearray(Path("encrypted_document.bin").read_bytes())
    encrypted_data[-1] ^= 1 # Modify one byte of the ciphertext
    Path("tampered_document.bin").write_bytes(encrypted_data)
    try:
        decrypt_file(
            "tampered_document.bin",
            "tampered_decryption.txt",
            aes_key
        )
        print("5. Tampering test: Failed")
    except InvalidTag:
        print("5. Tampering test: Passed - modified data rejected!")
