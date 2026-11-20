from digital_signatures import (
    generate_signing_key_pair,
    sign_document,
    verify_document,
    calculate_document_hash,
    save_private_key,
    load_private_key,
    save_public_key,
    load_public_key
)


print("=" * 50)
print("DIGITAL SIGNATURE AND VERIFICATION TEST")
print("=" * 50)

# STEP 1: Generate keys
private_key, public_key = generate_signing_key_pair()
print("\n1. Key pair generated successfully!")

# STEP 2: Create document
document = b"This is the original confidential report."
print("\n2. Original document:")
print(document.decode())

# STEP 3: Calculate SHA-256
document_hash = calculate_document_hash(document)
print("\n3. SHA-256 Hash:")
print(document_hash)

# STEP 4: Sign document
signature = sign_document(document, private_key)
print("\n4. Digital signature generated!")
print("Signature length:", len(signature), "bytes")

# STEP 5: Verify original document
result = verify_document(document, signature, public_key)
print("\n5. Original document verification:")
print("VALID" if result else "INVALID")

# STEP 6: Modify document
modified_document = b"This document has been modified!"
result = verify_document(modified_document, signature, public_key)
print("\n6. Modified document verification:")
print("VALID" if result else "INVALID - Tampering detected!")

# STEP 7: Wrong public key
_, wrong_public_key = generate_signing_key_pair()
result = verify_document(document, signature, wrong_public_key)
print("\n7. Wrong public key verification:")
print("VALID" if result else "INVALID - Wrong key detected!")

# STEP 8: Modify signature
modified_signature = bytes([signature[0] ^ 1]) + signature[1:]
result = verify_document(document, modified_signature, public_key)
print("\n8. Modified signature verification:")
print("VALID" if result else "INVALID - Signature tampering detected!")

# STEP 9: Save and reload keys
save_private_key(private_key, "alice_private.pem", "AliceSecure123!")
save_public_key(public_key, "alice_public.pem")

loaded_private_key = load_private_key(
    "alice_private.pem", "AliceSecure123!"
)
loaded_public_key = load_public_key("alice_public.pem")

loaded_signature = sign_document(document, loaded_private_key)

result = verify_document(document, loaded_signature, loaded_public_key)

print("\n9. Saved key verification:")
print("VALID" if result else "INVALID")

print("\nALL TESTS COMPLETED!")

