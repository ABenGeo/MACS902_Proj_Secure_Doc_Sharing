
from pathlib import Path

from digital_signatures import (
    generate_signing_key_pair,
    sign_document,
    verify_document,
    calculate_document_hash,
    save_private_key,
    save_public_key
)

# Locate the signatures folder
BASE_DIR = Path(__file__).resolve().parent

# Locate the actual document
document_path = BASE_DIR / "confidential_report.txt"

# STEP 1: Read the document
if not document_path.exists():
    raise FileNotFoundError("confidential_report.txt was not found!")

document_data = document_path.read_bytes()

print("=" * 55)
print("REAL DOCUMENT DIGITAL SIGNATURE TEST")
print("=" * 55)

print("\n1. Document loaded successfully!")
print("Filename:", document_path.name)
print("Document size:", len(document_data), "bytes")

# STEP 2: Generate Alice's keys
private_key, public_key = generate_signing_key_pair()

print("\n2. Alice's key pair generated!")

# STEP 3: Calculate SHA-256 hash
document_hash = calculate_document_hash(document_data)

print("\n3. SHA-256 Document Hash:")
print(document_hash)

# STEP 4: Digitally sign the document
signature = sign_document(document_data, private_key)

signature_path = BASE_DIR / "confidential_report.sig"
signature_path.write_bytes(signature)

print("\n4. Digital signature generated!")
print("Signature saved:", signature_path.name)

# STEP 5: Save Alice's keys
save_private_key(
    private_key,
    BASE_DIR / "alice_private.pem",
    "AliceSecure123!"
)

save_public_key(
    public_key,
    BASE_DIR / "alice_public.pem"
)

print("\n5. Alice's keys saved successfully!")

# STEP 6: Verify original document
result = verify_document(
    document_data,
    signature,
    public_key
)

print("\n6. Original document verification:")
print("VALID - Document is authentic!" if result else "INVALID")

# STEP 7: Modify the document in memory
modified_document = document_data + b"\nUNAUTHORIZED MODIFICATION!"

result = verify_document(
    modified_document,
    signature,
    public_key
)

print("\n7. Modified document verification:")
print(
    "VALID"
    if result
    else "INVALID - Document tampering detected!"
)

# STEP 8: Compare document hashes
modified_hash = calculate_document_hash(modified_document)

print("\n8. Hash comparison:")
print("Original hash:", document_hash)
print("Modified hash:", modified_hash)
print("Hashes match:", document_hash == modified_hash)

print("\n" + "=" * 55)
print("REAL DOCUMENT TEST COMPLETED!")
print("=" * 55)
