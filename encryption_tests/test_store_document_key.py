from db import get_connection

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    SELECT document_id, recipient_id, ephemeral_public_key,
           salt, nonce, protected_aes_key
    FROM document_keys
    ORDER BY rowid DESC
    LIMIT 1
""")

record = cursor.fetchone()

if record:
    print("Owner's protected AES key found!")
    print("Document ID:", record[0])
    print("Recipient ID:", record[1])
    print("Protected AES key stored:", bool(record[5]))
else:
    print("No protected key record found.")

connection.close()