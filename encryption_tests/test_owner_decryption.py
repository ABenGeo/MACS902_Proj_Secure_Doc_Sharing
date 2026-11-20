from db import get_connection
from keys import load_user_private_key, recover_recipient_aes_key
from encryption import decrypt_file
from pathlib import Path

alice_id = 1

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    SELECT d.document_id, d.original_filename,
           d.encrypted_file_path,
           k.ephemeral_public_key, k.salt,
           k.nonce, k.protected_aes_key
    FROM documents d
    JOIN document_keys k
        ON d.document_id = k.document_id
    WHERE d.owner_id = ? AND k.recipient_id = ?
    ORDER BY d.uploaded_at DESC
    LIMIT 1
""", (alice_id, alice_id))

record = cursor.fetchone()
connection.close()

if not record:
    print("No uploaded document with an owner key was found.")
    raise SystemExit

document_id, filename, encrypted_path = record[:3]

sharing_data = {
    "exchange_data": {
        "ephemeral_public_key": record[3],
        "salt": record[4]
    },
    "protected_key": {
        "nonce": record[5],
        "wrapped_key": record[6]
    }
}

password = input("Enter Alice's password: ")
alice_private_key = load_user_private_key(alice_id, password)
print("1. Alice's private key unlocked successfully!")

aes_key = recover_recipient_aes_key(
    sharing_data,
    alice_private_key,
    alice_id,
    alice_id,
    document_id
)
print("2. Alice recovered the AES key successfully!")

decrypted_path = Path(f"alice_recovered_{filename}")

decrypt_file(
    encrypted_path,
    decrypted_path,
    aes_key
)
print("3. Document decrypted successfully!")
print("Recovered document:", decrypted_path)