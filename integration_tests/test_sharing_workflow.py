from db import get_connection
from keys import (
    load_user_private_key,
    get_user_public_key,
    prepare_recipient_key,
    recover_recipient_aes_key
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

connection = get_connection()
cursor = connection.cursor()
cursor.execute(
    "SELECT user_id, username FROM users WHERE username IN (?, ?)",
    ("alice", "Bob")
)
users = {
    username: user_id
    for user_id, username in cursor.fetchall()
}
connection.close()
alice_id = users["alice"]
bob_id = users["Bob"]

bob_password = input("Enter Bob's password: ")
bob_private_key = load_user_private_key(bob_id, bob_password)
bob_public_key = get_user_public_key(bob_id)
print("\n1. Alice and Bob's accounts retrieved!")

aes_key = AESGCM.generate_key(bit_length=256)

sharing_data = prepare_recipient_key(
    aes_key,
    bob_public_key,
    alice_id,
    bob_id,
    "document_001"
)
print("2. Alice prepared the sharing data!")

recovered_aes_key = recover_recipient_aes_key(
    sharing_data,
    bob_private_key,
    alice_id,
    bob_id,
    "document_001"
)
print("3. Bob recovered the AES key!")
print("4. Original and recovered AES keys match:", aes_key == recovered_aes_key)