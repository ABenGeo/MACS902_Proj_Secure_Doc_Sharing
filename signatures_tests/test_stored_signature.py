from pathlib import Path
from db import get_connection
from keys import load_user_private_key, recover_recipient_aes_key
from encryption import decrypt_file
from digital_signatures import (
    load_user_signing_public_key,
    verify_document,
    calculate_document_hash
)

alice_id = 1
connection = get_connection()
cursor = connection.cursor()
cursor.execute("""
    SELECT d.document_id,
           d.original_filename,
           d.encrypted_file_path,
           d.digital_signature,
           d.document_hash,
           k.ephemeral_public_key,
           k.salt,
           k.nonce,
           k.protected_aes_key
    FROM documents d
    JOIN document_keys k
        ON d.document_id = k.document_id
    WHERE d.owner_id = ?
      AND k.recipient_id = ?
      AND d.digital_signature IS NOT NULL
    ORDER BY d.uploaded_at DESC
    LIMIT 1
""", (alice_id, alice_id))

record = cursor.fetchone()
connection.close()
if not record:
    raise Exception("No signed document with an owner key was found!")
(
    document_id,
    filename,
    encrypted_path,
    signature,
    stored_hash,
    ephemeral_public_key,
    salt,
    nonce,
    protected_aes_key
) = record
print("1. Signed document retrieved successfully!")

password = input("Enter Alice's password: ")
alice_private_key = load_user_private_key(
    alice_id, password
)
print("2. Alice's encryption private key unlocked!")

sharing_data = {
    "exchange_data": {
        "ephemeral_public_key": ephemeral_public_key,
        "salt": salt
    },
    "protected_key": {
        "nonce": nonce,
        "wrapped_key": protected_aes_key
    }
}
aes_key = recover_recipient_aes_key(
    sharing_data,
    alice_private_key,
    alice_id,
    alice_id,
    document_id
)
print("3. AES key recovered successfully!")

decrypted_path = Path(f"verification_test_{filename}")
decrypt_file(
    encrypted_path,
    decrypted_path,
    aes_key
)
print("4. Document decrypted successfully!")

alice_public_key = load_user_signing_public_key(alice_id)
document_data = decrypted_path.read_bytes()
signature_valid = verify_document(
    document_data,
    signature,
    alice_public_key
)
print("5. Digital signature verification:",
      "VALID" if signature_valid else "INVALID")

calculated_hash = calculate_document_hash(document_data)
print("6. SHA-256 hash verification:",
      "MATCH" if calculated_hash == stored_hash else "MISMATCH")

print("\nVerification test completed!")

# Testing document tampering
modified_document = document_data + b"\nUnauthorized modification!"
tampered_result = verify_document(
    modified_document,
    signature,
    alice_public_key
)
print(
    "7. Tampered document verification:",
    "VALID" if tampered_result
    else "INVALID - Tampering detected!"
)
