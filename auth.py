import sqlite3
import os
import hashlib
import base64
import hmac
from db import get_connection
from keys import create_and_store_user_keys, load_user_private_key
from digital_signatures import create_user_signing_keys
from digital_signatures import load_user_signing_private_key

def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )
    salt_encoded = base64.b64encode(salt).decode("utf-8")
    hash_encoded = base64.b64encode(password_hash).decode("utf-8")
    return f"{salt_encoded}${hash_encoded}"

def verify_password(password, stored_password): # Verify a password during login
    try:
        salt_encoded, hash_encoded = stored_password.split("$")
        salt = base64.b64decode(salt_encoded)
        stored_hash = base64.b64decode(hash_encoded)
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            600000
        )
        return hmac.compare_digest(new_hash, stored_hash)
    except (ValueError, TypeError):
        return False

def register_user(username, password):
    if not username or not password:
        return False, "Username and password are required."
    stored_password = hash_password(password)
    connection = get_connection()
    cursor = connection.cursor()
    user_id = None
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",(username, stored_password)
        )
        connection.commit()
        user_id = cursor.lastrowid # Gets the newly registered user's ID
        create_and_store_user_keys(user_id, password) # Generates and stores the user's encryption keys
        create_user_signing_keys(user_id, password) # Generates and stores the user's signing keys
        connection.close()
        return True, "Registration successful! Encryption keys generated."
    except sqlite3.IntegrityError:
        connection.close()
        return False, "Username already exists."
    except Exception:
        if user_id is not None:
            connection.execute(
                "DELETE FROM users WHERE user_id = ?", (user_id,)
            )
            connection.commit()
        connection.close()
        return False, "Registration failed. Please try again."

def login_user(username, password):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT user_id, password_hash FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    connection.close()
    if result and verify_password(password, result[1]):
        user_id = result[0]
        try:
            private_key = load_user_private_key(user_id, password)
            signing_private_key = load_user_signing_private_key(user_id, password)
            return (
                True,
                "Login successful! Encryption and signing keys unlocked.",
                user_id,
                private_key,
                signing_private_key
            )
        except Exception:
            return False, "Private keys could not be unlocked.", None, None, None
    return False, "Invalid username or password.", None, None, None
