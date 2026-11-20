from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from encryption import encrypt_uploaded_file

original_data = b"This is a test document for Streamlit upload."

aes_key = encrypt_uploaded_file(
    original_data,
    "test_upload.enc"
)
print("1. Document encrypted successfully!")

encrypted_data = Path("test_upload.enc").read_bytes()
nonce = encrypted_data[:12]
ciphertext = encrypted_data[12:]

decrypted_data = AESGCM(aes_key).decrypt(
    nonce,
    ciphertext,
    None
)

print("2. Document decrypted successfully!")
print("3. Original document recovered:", original_data == decrypted_data)