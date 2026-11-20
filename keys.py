from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
from db import get_connection
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from encryption import encrypt_file, decrypt_file
import base64
import os
import hashlib
import json

def generate_encryption_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    # Converts private key to bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Converts public key to bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return (
        base64.b64encode(private_bytes).decode("utf-8"),
        base64.b64encode(public_bytes).decode("utf-8")
    )

def encrypt_private_key(private_key_b64, password):
    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000,
        dklen=32
    )
    nonce = os.urandom(12)
    private_key_bytes = base64.b64decode(private_key_b64)
    encrypted_private_key = AESGCM(derived_key).encrypt(
        nonce,
        private_key_bytes,
        None
    )
    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "encrypted_private_key": base64.b64encode(
            encrypted_private_key
        ).decode("utf-8")
    }

def decrypt_private_key(protected_data, password):
    salt = base64.b64decode(protected_data["salt"])
    nonce = base64.b64decode(protected_data["nonce"])
    encrypted_private_key = base64.b64decode(
        protected_data["encrypted_private_key"]
    )
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000,
        dklen=32
    )
    private_key_bytes = AESGCM(derived_key).decrypt(
        nonce,
        encrypted_private_key,
        None
    )
    return x25519.X25519PrivateKey.from_private_bytes(
        private_key_bytes
    )

def create_and_store_user_keys(user_id, password):
    private_key, public_key = generate_encryption_key_pair()
    protected_data = encrypt_private_key(private_key, password) # Encrypts the private key using the user's password
    # Create a local folder for protected private keys
    key_directory = Path("private_keys")
    key_directory.mkdir(exist_ok=True)
    key_file = key_directory / f"user_{user_id}.json" # Saves the encrypted private key locally
    with open(key_file, "w") as file:
        json.dump(protected_data, file)
    # Saves the public key in the database
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO user_encryption_keys (user_id, public_key)
        VALUES (?, ?)
        """,
        (user_id, public_key)
    )
    connection.commit()
    connection.close()
    return "User encryption keys created successfully!"

def load_user_private_key(user_id, password):
    key_file = Path("private_keys") / f"user_{user_id}.json"
    if not key_file.exists():
        raise FileNotFoundError("Private key not found.")
    with open(key_file, "r") as file:
        protected_data = json.load(file)
    private_key = decrypt_private_key(protected_data, password) # Decrypt and load the private key
    return private_key

def get_user_public_key(user_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT public_key
        FROM user_encryption_keys
        WHERE user_id = ?
        """,
        (user_id,)
    )
    result = cursor.fetchone()
    connection.close()
    if result is None:
        raise ValueError("Public key not found for this user.")
    public_key_bytes = base64.b64decode(result[0])
    return x25519.X25519PublicKey.from_public_bytes(
        public_key_bytes
    )

def create_recipient_wrapping_key(
        recipient_public_key,
        sender_id,
        recipient_id,
        document_id
):
    # Generates a temporary X25519 key pair for the sharing operation
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()
    shared_secret = ephemeral_private_key.exchange(
        recipient_public_key
    )
    salt = os.urandom(16)
    # Binds the derived key to the sender, recipient and document
    context = (
        f"document-sharing-v1|"
        f"sender:{sender_id}|"
        f"recipient:{recipient_id}|"
        f"document:{document_id}"
    ).encode("utf-8")
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=context
    ).derive(shared_secret)
    # Stores the information the recipient needs to derive the same key
    exchange_data = {
        "ephemeral_public_key": base64.b64encode(
            ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode("utf-8"),
        "salt": base64.b64encode(salt).decode("utf-8")
    }
    return wrapping_key, exchange_data

def recover_recipient_wrapping_key(
        recipient_private_key,
        exchange_data,
        sender_id,
        recipient_id,
        document_id
):
    # Retrieves the sender's temporary public key
    ephemeral_public_bytes = base64.b64decode(
        exchange_data["ephemeral_public_key"]
    )
    ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
        ephemeral_public_bytes
    )
    salt = base64.b64decode(exchange_data["salt"])
    shared_secret = recipient_private_key.exchange(
        ephemeral_public_key
    )
    context = (
        f"document-sharing-v1|"
        f"sender:{sender_id}|"
        f"recipient:{recipient_id}|"
        f"document:{document_id}"
    ).encode("utf-8")
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=context
    ).derive(shared_secret)
    return wrapping_key

def prepare_recipient_key(
        aes_key,
        recipient_public_key,
        sender_id,
        recipient_id,
        document_id
):
    wrapping_key, exchange_data = create_recipient_wrapping_key(
        recipient_public_key,
        sender_id,
        recipient_id,
        document_id
    )
    protected_key = wrap_aes_key(
        aes_key,
        wrapping_key
    )
    return {
        "exchange_data": exchange_data,
        "protected_key": protected_key
    }

def recover_recipient_aes_key(
        sharing_data,
        recipient_private_key,
        sender_id,
        recipient_id,
        document_id
):
    wrapping_key = recover_recipient_wrapping_key(
        recipient_private_key,
        sharing_data["exchange_data"],
        sender_id,
        recipient_id,
        document_id
    )
    aes_key = unwrap_aes_key(
        sharing_data["protected_key"],
        wrapping_key
    )
    return aes_key

def derive_wrapping_key(shared_secret, salt):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"document-key-wrapping"
    )
    return hkdf.derive(shared_secret)

def wrap_aes_key(aes_key, wrapping_key):
    nonce = os.urandom(12)
    aesgcm = AESGCM(wrapping_key)
    wrapped_key = aesgcm.encrypt(
        nonce,
        aes_key,
        None
    )
    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "wrapped_key": base64.b64encode(wrapped_key).decode("utf-8")
    }

def unwrap_aes_key(protected_data, wrapping_key):
    nonce = base64.b64decode(protected_data["nonce"])
    wrapped_key = base64.b64decode(protected_data["wrapped_key"])
    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(
        nonce,
        wrapped_key,
        None
    )

def protect_and_store_document_key(
    aes_key,
    sender_id,
    recipient_id,
    document_id
):
    recipient_public_key = get_user_public_key(recipient_id)
    # Protects the AES key specifically for this recipient
    sharing_data = prepare_recipient_key(
        aes_key,
        recipient_public_key,
        sender_id,
        recipient_id,
        document_id
    )
    exchange_data = sharing_data["exchange_data"]
    protected_key = sharing_data["protected_key"]
    connection = get_connection() # Stores the protected AES key and exchange metadata
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO document_keys (
                document_id,
                recipient_id,
                ephemeral_public_key,
                salt,
                nonce,
                protected_aes_key
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                document_id,
                recipient_id,
                exchange_data["ephemeral_public_key"],
                exchange_data["salt"],
                protected_key["nonce"],
                protected_key["wrapped_key"]
            )
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return True

if __name__ == "__main__":
    private_key, public_key = generate_encryption_key_pair()
    print("1. Encryption key pair generated successfully!")

    password = "Alice@123"
    protected_data = encrypt_private_key(private_key, password)
    print("2. Private key encrypted successfully!")

    decrypted_private_key = decrypt_private_key(
        protected_data,
        password
    )
    print("3. Private key decrypted successfully!")

    # Checks whether the recovered private key matches the original private key
    recovered_private_bytes = decrypted_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    original_private_bytes = base64.b64decode(private_key)
    print("4. Private key recovery verified:", recovered_private_bytes == original_private_bytes)

    # Testing for key pair generation and exchange
    alice_private, alice_public = generate_encryption_key_pair() # Generates Alice's X25519 key pair
    bob_private, bob_public = generate_encryption_key_pair() # Generates Bob's X25519 key pair
    # Reconstruct the private and public key objects
    alice_private_key = x25519.X25519PrivateKey.from_private_bytes(
        base64.b64decode(alice_private)
    )
    alice_public_key = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(alice_public)
    )
    bob_private_key = x25519.X25519PrivateKey.from_private_bytes(
        base64.b64decode(bob_private)
    )
    bob_public_key = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(bob_public)
    )
    alice_shared_secret = alice_private_key.exchange(bob_public_key)
    bob_shared_secret = bob_private_key.exchange(alice_public_key)
    # Compare both shared secrets
    print("Shared secret generated by Alice:", alice_shared_secret.hex())
    print("Shared secret generated by Bob:  ", bob_shared_secret.hex())
    print("Shared secret matches:", alice_shared_secret == bob_shared_secret)

    # Derive wrapping keys using HKDF
    salt = os.urandom(16)
    alice_wrapping_key = derive_wrapping_key(
        alice_shared_secret, salt
    )
    bob_wrapping_key = derive_wrapping_key(
        bob_shared_secret, salt
    )
    print("HKDF wrapping keys match:", alice_wrapping_key == bob_wrapping_key)

    # Testing for AES key wrapping and unwrapping
    document_aes_key = AESGCM.generate_key(bit_length=256) # Generates a sample AES-256 document key
    # Alice protects the AES key
    protected_aes_key = wrap_aes_key(
        document_aes_key,
        alice_wrapping_key
    )
    print("AES key wrapped successfully!")
    # Bob recovers the AES key
    recovered_aes_key = unwrap_aes_key(
        protected_aes_key,
        bob_wrapping_key
    )
    print("AES key unwrapped successfully!")
    print("AES key recovery verified:", document_aes_key == recovered_aes_key) # Verifies that Bob recovered the original AES key

    # Complete Alice to Bob document sharing test
    document_aes_key = encrypt_file(
        "confidential_document.txt",
        "alice_encrypted_document.bin"
    )
    print("1. Alice encrypted the document successfully!")
    protected_aes_key = wrap_aes_key(
        document_aes_key,
        alice_wrapping_key
    )
    print("2. Alice protected the AES key successfully!")
    bob_aes_key = unwrap_aes_key(
        protected_aes_key,
        bob_wrapping_key
    )
    print("3. Bob recovered the AES key successfully!")
    decrypt_file(
        "alice_encrypted_document.bin",
        "bob_decrypted_document.txt",
        bob_aes_key
    )
    print("4. Bob decrypted the document successfully!")
    # Verifying the recovered document
    original = Path("confidential_document.txt").read_bytes()
    recovered = Path("bob_decrypted_document.txt").read_bytes()
    print("5. Document recovery verified:", original == recovered)
