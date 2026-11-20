from pathlib import Path
from digital_signatures import (
    load_public_key,
    verify_document,
    calculate_document_hash
)

BASE_DIR = Path(__file__).resolve().parent
document_path = BASE_DIR / "confidential_report.txt"
signature_path = BASE_DIR / "confidential_report.sig"
public_key_path = BASE_DIR / "alice_public.pem"

print("=" * 55)
print("BOB - DOCUMENT SIGNATURE VERIFICATION")
print("=" * 55)

if not document_path.exists():
    raise FileNotFoundError("Document not found!")
if not signature_path.exists():
    raise FileNotFoundError("Digital signature not found!")
if not public_key_path.exists():
    raise FileNotFoundError("Alice's public key not found!")

document_data = document_path.read_bytes()
signature = signature_path.read_bytes()
print("\n1. Bob received the document!")
print("Document:", document_path.name)
print("Signature:", signature_path.name)

# Load Alice's public key
alice_public_key = load_public_key(public_key_path)
print("\n2. Alice's public key loaded successfully!")

# Calculates document fingerprint
document_hash = calculate_document_hash(document_data)
print("\n3. Document SHA-256 fingerprint:")
print(document_hash)

# Verifies Alice's signature
result = verify_document(
    document_data,
    signature,
    alice_public_key
)
print("\n4. Digital signature verification:")
if result:
    print("VALID - Alice's signature is verified!")
    print("The document has not been modified.")
else:
    print("INVALID - Signature verification failed!")

# Checks document tampering
tampered_document = (
    document_data + b"\nUnauthorized changes made by an attacker."
)
tampered_result = verify_document(
    tampered_document,
    signature,
    alice_public_key
)
print("\n5. Tampered document verification:")
if tampered_result:
    print("VALID")
else:
    print("INVALID - Unauthorized modification detected!")

print("\n" + "=" * 55)
print("BOB VERIFICATION COMPLETED!")
print("=" * 55)
