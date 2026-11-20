from digital_signatures import (
    load_user_signing_private_key,
    load_user_signing_public_key,
    sign_document,
    verify_document
)

alice_password = input("Enter Alice's password: ")
alice_private = load_user_signing_private_key(
    1, alice_password
)
alice_public = load_user_signing_public_key(1)
document = b"This is Alice's confidential document."
signature = sign_document(document, alice_private)
print("\n1. Alice's document signed successfully!")

result = verify_document(document, signature, alice_public)
print("2. Alice's signature verification:",
      "VALID" if result else "INVALID")

bob_public = load_user_signing_public_key(2)
result = verify_document(document, signature, bob_public)
print("3. Verification using Bob's public key:",
      "VALID" if result else "INVALID")

modified_document = document + b" Modified!"
result = verify_document(
    modified_document, signature, alice_public
)
print("4. Modified document verification:",
      "VALID" if result else "INVALID - Tampering detected!")