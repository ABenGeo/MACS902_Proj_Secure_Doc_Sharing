from db import get_connection
from keys import (
    load_user_private_key,
    get_user_public_key,
    generate_encryption_key_pair,
    create_recipient_wrapping_key,
    recover_recipient_wrapping_key
)
from cryptography.hazmat.primitives.asymmetric import x25519
from keys import wrap_aes_key, unwrap_aes_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import base64

connection = get_connection()
cursor = connection.cursor()
cursor.execute("SELECT user_id, username FROM users")
users = cursor.fetchall()
connection.close()
user_ids = {
    username.lower(): user_id
    for user_id, username in users
}
alice_id = user_ids["alice"]
bob_id = user_ids["bob"]

bob_password = input("Enter Bob's password: ")
bob_private_key = load_user_private_key(bob_id, bob_password)
print("\n1. Bob's private key unlocked successfully!")

bob_public_key = get_user_public_key(bob_id)
print("2. Bob's public key retrieved successfully!")

document_id = "document_001"
alice_wrapping_key, exchange_data = create_recipient_wrapping_key(
    bob_public_key,
    alice_id,
    bob_id,
    document_id
)
print("3. Alice created a wrapping key for Bob!")

bob_wrapping_key = recover_recipient_wrapping_key(
    bob_private_key,
    exchange_data,
    alice_id,
    bob_id,
    document_id
)
print("4. Bob derived his wrapping key!")

print(
    "5. Alice and Bob's wrapping keys match:",
    alice_wrapping_key == bob_wrapping_key
)

charlie_private_b64, charlie_public_b64 = (
    generate_encryption_key_pair()
)
charlie_private_key = x25519.X25519PrivateKey.from_private_bytes(
    base64.b64decode(charlie_private_b64)
)
print("\n6. Temporary key pair generated for Charlie!")

try:
    charlie_wrapping_key = recover_recipient_wrapping_key(
        charlie_private_key,
        exchange_data,
        alice_id,
        bob_id,
        document_id
    )
    print(
        "7. Charlie derived Bob's wrapping key:",
        charlie_wrapping_key == alice_wrapping_key
    )
except Exception:
    print("7. Charlie could not derive Bob's wrapping key.")

if 'charlie_wrapping_key' in locals():
    print(
        "8. Charlie's key differs from Bob's key:",
        charlie_wrapping_key != bob_wrapping_key
    )
else:
    print("8. Charlie could not recover the correct wrapping key.")

document_aes_key = AESGCM.generate_key(bit_length=256)
print("\n9. Document AES-256 key generated!")

protected_aes_key = wrap_aes_key(
    document_aes_key,
    alice_wrapping_key
)
print("10. Alice protected the AES key for Bob!")

bob_recovered_key = unwrap_aes_key(
    protected_aes_key,
    bob_wrapping_key
)
print(
    "11. Bob recovered the original AES key:",
    bob_recovered_key == document_aes_key
)

try:
    charlie_recovered_key = unwrap_aes_key(
        protected_aes_key,
        charlie_wrapping_key
    )
    print("12. Charlie recovered the AES key:",
          charlie_recovered_key == document_aes_key)
except InvalidTag:
    print("12. Charlie's attempt rejected: AES-GCM authentication failed!")
