# MACS902 – Secure Multi-User Document Sharing System

A Python-based secure document-sharing application developed as part of the MACS902 Cryptography Group Project.

## Features

- User registration and login with password hashing.
- AES-256-GCM document encryption and decryption.
- X25519 key exchange and HKDF-based key derivation.
- Ed25519 digital signatures and verification.
- Secure document sharing between registered users.
- Access control and permission revocation.
- Document integrity and tampering detection using AES-GCM, digital signatures and SHA-256 hashing.

## Technologies Used

- Python
- Streamlit
- SQLite
- Cryptography library

## Project Structure

- `main.py` – Application entry point and authentication interface.
- `dashboard.py` – Document upload, sharing and access management interface.
- `auth.py` – User authentication and password hashing.
- `db.py` – Database connection and table creation.
- `encryption.py` – Document encryption and decryption.
- `keys.py` – Cryptographic key management.
- `digital_signatures.py` – Digital signature generation and verification.
- `access_control/` – Sharing permissions and access revocation.
- `requirements.txt` – Project dependencies.

## Running the Application

Install the dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
streamlit run main.py
```

## Project Status

The integrated prototype has been implemented and functionally tested.
