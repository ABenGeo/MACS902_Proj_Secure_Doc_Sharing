
import sqlite3

from permissions import (
    create_permissions_table,
    share_document,
    check_access,
    revoke_access
)


# Create a temporary in-memory SQLite database
connection = sqlite3.connect(":memory:")

cursor = connection.cursor()

# Create test users table
cursor.execute("""
    CREATE TABLE users (
        user_id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL
    )
""")

# Create test documents table
cursor.execute("""
    CREATE TABLE documents (
        document_id TEXT PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES users(user_id)
    )
""")

# Insert Alice, Bob and Charlie
cursor.executemany("""
    INSERT INTO users (user_id, username)
    VALUES (?, ?)
""", [
    (1, "Alice"),
    (2, "Bob"),
    (3, "Charlie")
])

# Alice owns document 101
cursor.execute("""
    INSERT INTO documents (document_id, owner_id)
    VALUES (?, ?)
""", ("101", 1))

connection.commit()

# Create permissions table
create_permissions_table(connection)


print("\n--- ACCESS CONTROL TESTING ---\n")

# Test 1: Alice shares document with Bob
result = share_document(1, "101", 2, connection)
print("Test 1 - Alice shares with Bob:", result)

# Test 2: Bob requests document
result = check_access(2, "101", connection)
print("Test 2 - Bob access:", result)

# Test 3: Charlie requests document
result = check_access(3, "101", connection)
print("Test 3 - Charlie access:", result)

# Test 4: Alice revokes Bob's access
result = revoke_access(1, "101", 2, connection)
print("Test 4 - Alice revokes Bob:", result)

# Test 5: Bob requests document again
result = check_access(2, "101", connection)
print("Test 5 - Bob access after revocation:", result)

# Test 6: Charlie attempts to revoke access
result = revoke_access(3, "101", 2, connection)
print("Test 6 - Charlie attempts revocation:", result)

# Test 7: Alice attempts to share with a nonexistent user
result = share_document(1, "101", 99, connection)
print("Test 7 - Share with nonexistent user:", result)

# Test 8: Alice (owner) always has access
result = check_access(1, "101", connection)
print("Test 8 - Owner access:", result)

# Test 9: Bob attempts to share Alice's document
result = share_document(2, "101", 3, connection)
print("Test 9 - Non-owner attempts sharing:", result)

# Test 10: Alice attempts to share with herself
result = share_document(1, "101", 1, connection)
print("Test 10 - Self-sharing:", result)

# Test 11: Duplicate sharing
# First, Alice restores Bob's revoked access
result = share_document(1, "101", 2, connection)
print("Test 11a - Restore Bob's access:", result)

# Then, Alice tries sharing with Bob again
result = share_document(1, "101", 2, connection)
print("Test 11b - Duplicate sharing:", result)

connection.close()
