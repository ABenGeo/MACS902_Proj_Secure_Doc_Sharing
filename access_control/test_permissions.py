import sqlite3
from permissions import (
    create_permissions_table,
    share_document,
    check_access,
    revoke_access
)
connection = sqlite3.connect(":memory:")

cursor = connection.cursor()
cursor.execute("""
    CREATE TABLE users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
""")
cursor.execute("""
    CREATE TABLE documents (
        document_id TEXT PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        original_filename TEXT NOT NULL,
        encrypted_file_path TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(user_id)
    )
""")
cursor.executemany("""
    INSERT INTO users (user_id, username, password_hash)
    VALUES (?, ?, ?)
""", [
    (1, "Alice", "alice_test_hash"),
    (2, "Bob", "bob_test_hash"),
    (3, "Charlie", "charlie_test_hash")
])
cursor.execute("""
    INSERT INTO documents (
        document_id,
        owner_id,
        original_filename,
        encrypted_file_path
    )
    VALUES (?, ?, ?, ?)
""", ("101", 1, "test_document.pdf", "encrypted/test_document.pdf"))

connection.commit()
create_permissions_table(connection)
print("\n--- ACCESS CONTROL TESTING ---\n")

result = share_document(1, "101", 2, connection)
print("Test 1 - Alice shares with Bob:", result)

result = check_access(2, "101", connection)
print("Test 2 - Bob access:", result)

result = check_access(3, "101", connection)
print("Test 3 - Charlie access:", result)

result = revoke_access(1, "101", 2, connection)
print("Test 4 - Alice revokes Bob:", result)

result = check_access(2, "101", connection)
print("Test 5 - Bob access after revocation:", result)

result = revoke_access(3, "101", 2, connection)
print("Test 6 - Charlie attempts revocation:", result)

result = share_document(1, "101", 99, connection)
print("Test 7 - Share with nonexistent user:", result)

result = check_access(1, "101", connection)
print("Test 8 - Owner access:", result)

result = share_document(2, "101", 3, connection)
print("Test 9 - Non-owner attempts sharing:", result)

result = share_document(1, "101", 1, connection)
print("Test 10 - Self-sharing:", result)

result = share_document(1, "101", 2, connection)
print("Test 11a - Restore Bob's access:", result)

result = share_document(1, "101", 2, connection)
print("Test 11b - Duplicate sharing:", result)
connection.close()
