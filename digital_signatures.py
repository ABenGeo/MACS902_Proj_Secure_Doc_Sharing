from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def generate_signing_key_pair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, file_path, password):
    if not password:
        raise ValueError("Password is required.")
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )
    Path(file_path).write_bytes(pem_data)

def load_private_key(file_path, password):
    pem_data = Path(file_path).read_bytes()
    return serialization.load_pem_private_key(
        pem_data,
        password=password.encode("utf-8")
    )

def save_public_key(public_key, file_path):
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(file_path).write_bytes(pem_data)

def load_public_key(file_path):
    pem_data = Path(file_path).read_bytes()
    return serialization.load_pem_public_key(pem_data)

def calculate_document_hash(document_data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(document_data)
    return digest.finalize().hex()

def sign_document(document_data, private_key):
    signature = private_key.sign(document_data)
    return signature

def verify_document(document_data, signature, public_key):
    try:
        public_key.verify(signature, document_data)
        return True
    except InvalidSignature:
        return False


def create_user_signing_keys(user_id, password):
    signing_folder = Path("signing_keys")
    signing_folder.mkdir(exist_ok=True)

    private_key_path = signing_folder / f"user_{user_id}_private.pem"
    public_key_path = signing_folder / f"user_{user_id}_public.pem"

    if private_key_path.exists() or public_key_path.exists():
        raise FileExistsError("Signing keys already exist for this user.")

    private_key, public_key = generate_signing_key_pair()

    save_private_key(private_key, private_key_path, password)
    save_public_key(public_key, public_key_path)

    return True


def load_user_signing_private_key(user_id, password):
    private_key_path = (
        Path("signing_keys") / f"user_{user_id}_private.pem"
    )

    return load_private_key(private_key_path, password)


def load_user_signing_public_key(user_id):
    public_key_path = (
        Path("signing_keys") / f"user_{user_id}_public.pem"
    )

    return load_public_key(public_key_path)
