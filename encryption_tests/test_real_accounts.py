import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from db import get_connection
from keys import (
    load_user_private_key,
    wrap_aes_key,
    unwrap_aes_key
)
from encryption import encrypt_file, decrypt_file
from auth import login_user

connection = get_connection()
cursor = connection.cursor()
alice_username = input("Enter Alice's username: ")
bob_username = input("Enter Bob's username: ")
cursor.execute("""
    SELECT u.user_id, k.public_key
    FROM users u
    JOIN user_encryption_keys k ON u.user_id = k.user_id
    WHERE u.username = ?
""", (alice_username,))
alice = cursor.fetchone()
cursor.execute("""
    SELECT u.user_id, k.public_key
    FROM users u
    JOIN user_encryption_keys k ON u.user_id = k.user_id
    WHERE u.username = ?
""", (bob_username,))
bob = cursor.fetchone()
connection.close()
if not alice or not bob:
    raise Exception("Alice or Bob was not found, or their public key is missing.")
alice_id, alice_public_b64 = alice
bob_id, bob_public_b64 = bob
print("\n1. Registered user details retrieved successfully!")

alice_password = input("Enter Alice's password: ")
bob_password = input("Enter Bob's password: ")
alice_private = load_user_private_key(alice_id, alice_password)
bob_private = load_user_private_key(bob_id, bob_password)
print("2. Alice's and Bob's private keys unlocked successfully!")

alice_public = x25519.X25519PublicKey.from_public_bytes(
    base64.b64decode(alice_public_b64)
)
bob_public = x25519.X25519PublicKey.from_public_bytes(
    base64.b64decode(bob_public_b64)
)

alice_shared_secret = alice_private.exchange(bob_public)
bob_shared_secret = bob_private.exchange(alice_public)
print("\n3. Alice and Bob performed X25519 key exchange.")
print("Shared secrets match:", alice_shared_secret == bob_shared_secret)
if alice_shared_secret != bob_shared_secret:
    raise Exception("Key exchange failed!")

salt = __import__("os").urandom(16)
context = (
    f"document-sharing|sender:{alice_id}|"
    f"recipient:{bob_id}|document:confidential_document.txt"
).encode("utf-8")
def derive_context_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=context
    ).derive(shared_secret)
alice_wrapping_key = derive_context_key(alice_shared_secret)
bob_wrapping_key = derive_context_key(bob_shared_secret)
print("4. HKDF wrapping keys match:", alice_wrapping_key == bob_wrapping_key)

aes_key = encrypt_file(
    "confidential_document.txt",
    "real_alice_encrypted.bin"
)
print("\n5. Alice encrypted the document successfully!")

protected_key = wrap_aes_key(aes_key, alice_wrapping_key)
print("6. Alice protected the AES key for Bob!")

recovered_aes_key = unwrap_aes_key(
    protected_key,
    bob_wrapping_key
)
print("7. Bob recovered the AES key successfully!")

decrypt_file(
    "real_alice_encrypted.bin",
    "real_bob_decrypted.txt",
    recovered_aes_key
)
print("8. Bob decrypted the document successfully!")

original = Path("confidential_document.txt").read_bytes()
recovered = Path("real_bob_decrypted.txt").read_bytes()
print("9. Document recovery verified:", original == recovered)

print("\nLogin Function Test")
success, message, user_id, private_key = login_user(
    "alice",
    input("Enter Alice's password again: ")
)
print("Login result:", message)
if success:
    print("User ID:", user_id)
    print("Private key unlocked:", private_key is not None)
    print("Private key type:", type(private_key).__name__)