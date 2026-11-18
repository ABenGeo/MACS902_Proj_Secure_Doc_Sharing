
# MACS902 – Secure Document Sharing System

A secure document-sharing system developed as part of the MACS902 project.

## Project Structure

- `access_control/` – Document ownership, sharing permissions, access verification and revocation.
- `Database/` – Database operations and storage.
- `Encryption/` – Cryptographic operations.

## Access Control Implementation

The access-control module is implemented using Python and SQLite.

It includes:
- Document ownership verification.
- Document sharing with other users.
- Recipient access verification.
- Permission revocation.
- Validation against unauthorized and duplicate sharing.

## Testing

The access-control module has been tested using an in-memory SQLite database.

All 11 test scenarios passed, including ownership checks, sharing, access verification and revocation.

## Project Status

Initial project setup and access-control implementation completed. Database and encryption integration are in progress.
