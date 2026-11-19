import sqlite3

database_name = "secure_sharing.db"

def get_connection():
    return sqlite3.connect(database_name)

def create_tables():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_encryption_keys (
            user_id INTEGER PRIMARY KEY,
            public_key TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_file_path TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(user_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS document_keys (
            document_id TEXT NOT NULL,
            recipient_id INTEGER NOT NULL,
            ephemeral_public_key TEXT NOT NULL,
            salt TEXT NOT NULL,
            nonce TEXT NOT NULL,
            protected_aes_key TEXT NOT NULL,
            PRIMARY KEY (document_id, recipient_id),
            FOREIGN KEY (document_id) REFERENCES documents(document_id),
            FOREIGN KEY (recipient_id) REFERENCES users(user_id)
        )
    """)
    connection.commit()
    connection.close()

if __name__ == "__main__":
    create_tables()
    print("Database and tables created successfully!")