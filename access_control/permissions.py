def create_permissions_table(db_connection):
    cursor = db_connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            UNIQUE(document_id, recipient_id)
        )
    """)

    db_connection.commit()

def share_document(owner_id: int, document_id: str,
                   recipient_id: int, db_connection):

    cursor = db_connection.cursor()
    cursor.execute("""
        SELECT owner_id FROM documents
        WHERE document_id = ?
    """, (document_id,))

    document = cursor.fetchone()

    if document is None:
        return False, "Document not found."

    if document[0] != owner_id:
        return False, "Only the document owner can share this document."

    if owner_id == recipient_id:
        return False, "You cannot share a document with yourself."

    cursor.execute("""
        SELECT user_id FROM users
        WHERE user_id = ?
    """, (recipient_id,))

    recipient = cursor.fetchone()

    if recipient is None:
        return False, "Recipient user not found."
    cursor.execute("""
        SELECT status FROM permissions
        WHERE document_id = ? AND recipient_id = ?
    """, (document_id, recipient_id))

    existing = cursor.fetchone()

    if existing and existing[0] == "active":
        return False, "User already has access."

    if existing:
        cursor.execute("""
            UPDATE permissions
            SET owner_id = ?, status = 'active'
            WHERE document_id = ? AND recipient_id = ?
        """, (owner_id, document_id, recipient_id))

    else:
        cursor.execute("""
            INSERT INTO permissions
            (document_id, owner_id, recipient_id, status)
            VALUES (?, ?, ?, 'active')
        """, (document_id, owner_id, recipient_id))

    db_connection.commit()

    return True, "Document shared successfully."

def check_access(user_id: int, document_id: str, db_connection):
    cursor = db_connection.cursor()
    cursor.execute("""
        SELECT owner_id FROM documents
        WHERE document_id = ?
    """, (document_id,))

    document = cursor.fetchone()

    if document is None:
        return False

    if document[0] == user_id:
        return True

    cursor.execute("""
        SELECT status FROM permissions
        WHERE document_id = ? AND recipient_id = ?
    """, (document_id, user_id))

    permission = cursor.fetchone()

    return permission is not None and permission[0] == "active"


def revoke_access(owner_id: int, document_id: str,
                  recipient_id: int, db_connection):
    cursor = db_connection.cursor()
    cursor.execute("""
        SELECT owner_id FROM documents
        WHERE document_id = ?
    """, (document_id,))

    document = cursor.fetchone()

    if document is None:
        return False, "Document not found."

    if document[0] != owner_id:
        return False, "Only the document owner can revoke access."

    cursor.execute("""
        SELECT status FROM permissions
        WHERE document_id = ? AND recipient_id = ?
    """, (document_id, recipient_id))

    permission = cursor.fetchone()

    if permission is None or permission[0] != "active":
        return False, "No active permission found."

    cursor.execute("""
        UPDATE permissions
        SET status = 'revoked'
        WHERE document_id = ? AND recipient_id = ?
    """, (document_id, recipient_id))

    db_connection.commit()
    return True, "Access revoked successfully."

