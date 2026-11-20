from db import get_connection
from encryption import encrypt_file, decrypt_file
from keys import (
    load_user_private_key,
    get_user_public_key,
    prepare_recipient_key,
    recover_recipient_aes_key
)

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

aes_key = encrypt_file(
    "confidential_document.txt",
    "confidential_document.enc"
)
print("2. Alice encrypted the document!")

sharing_data = prepare_recipient_key(
    aes_key,
    bob_public_key,
    alice_id,
    bob_id,
    "document_001"
)
print("3. Alice protected the AES key for Bob!")

recovered_aes_key = recover_recipient_aes_key(
    sharing_data,
    bob_private_key,
    alice_id,
    bob_id,
    "document_001"
)
print("4. Bob recovered the AES key!")

decrypt_file(
    "confidential_document.enc",
    "bob_decrypted_document.txt",
    recovered_aes_key
)
print("5. Bob decrypted the document!")

with open("confidential_document.txt", "rb") as original:
    original_data = original.read()

with open("bob_decrypted_document.txt", "rb") as decrypted:
    decrypted_data = decrypted.read()

print("6. Document recovery verified:", original_data == decrypted_data)
