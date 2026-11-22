import streamlit as st
from db import get_connection
from access_control.permissions import (
    share_document,
    check_access,
    revoke_access
)
from pathlib import Path
import uuid
from encryption import encrypt_uploaded_file, decrypt_file
from keys import (
    protect_and_store_document_key,
    recover_recipient_aes_key)
from digital_signatures import (
    sign_document,
    calculate_document_hash,
    load_user_signing_public_key,
    verify_document
)

def show_dashboard(username, user_id, private_key):
    st.markdown(
        f"<h2 style='font-weight: 700;'>Welcome, {username}!</h2>",
        unsafe_allow_html=True
    )
    if "flash_message" in st.session_state:
        st.success(st.session_state.pop("flash_message"))
    st.divider()

    st.subheader("Upload & Protect Document")
    st.write(
        "Upload your document to encrypt it and apply a digital signature."
    )
    uploaded_file = st.file_uploader(
        "Choose a document",
        type=["pdf", "docx", "txt", "jpg", "png", "xlsx"],
        key="document_upload"
    )
    if uploaded_file is not None:
        st.success("Document selected successfully!")
        st.write("**Filename:**", uploaded_file.name)
        st.write("**File size:**", uploaded_file.size, "bytes")
        st.caption(
            "The document will be encrypted and digitally signed."
        )
        if st.button("Upload & Encrypt", key="encrypt_document"):
            document_id = str(uuid.uuid4())
            encrypted_folder = Path("encrypted_documents")
            encrypted_path = encrypted_folder / f"{document_id}.enc"
            try:
                file_data = uploaded_file.getvalue() # Reads the uploaded document
                document_hash = calculate_document_hash(file_data)
                signing_private_key = st.session_state.signing_private_key
                signature = sign_document(file_data, signing_private_key)
                aes_key = encrypt_uploaded_file(file_data, encrypted_path)
                # Saves the document metadata in SQLite
                connection = get_connection()
                cursor = connection.cursor()
                cursor.execute(
                    """
                    INSERT INTO documents (
                        document_id,
                        owner_id,
                        original_filename,
                        encrypted_file_path,
                        digital_signature,
                        document_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        document_id,
                        user_id,
                        uploaded_file.name,
                        str(encrypted_path),
                        signature,
                        document_hash
                    )
                )
                connection.commit()
                connection.close()
                # Protects the AES key for the document owner
                protect_and_store_document_key(
                    aes_key,
                    user_id,
                    user_id,
                    document_id
                )
                st.success("Document encrypted and AES key securely protected!")
                st.success("Digital signature generated successfully!")
                st.info("Security status: Encrypted and Digitally Signed")
            except Exception as e:
                if encrypted_path.exists():
                    encrypted_path.unlink()
                st.error(f"Document upload failed: {e}")
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT document_id, original_filename
        FROM documents
        WHERE owner_id = ?
    """, (user_id,))
    documents = cursor.fetchall()
    cursor.execute("""
        SELECT user_id, username
        FROM users
        WHERE user_id != ?
    """, (user_id,))
    users = cursor.fetchall()
    cursor.execute("""
        SELECT p.document_id, d.original_filename,
               p.recipient_id, u.username
        FROM permissions p
        JOIN documents d ON p.document_id = d.document_id
        JOIN users u ON p.recipient_id = u.user_id
        WHERE p.owner_id = ? AND p.status = 'active'
    """, (user_id,))
    active_shares = cursor.fetchall()
    cursor.execute("""
        SELECT d.document_id,
               d.original_filename,
               d.encrypted_file_path,
               d.owner_id,
               u.username
        FROM permissions p
        JOIN documents d ON p.document_id = d.document_id
        JOIN users u ON d.owner_id = u.user_id
        WHERE p.recipient_id = ?
          AND p.status = 'active'
    """, (user_id,))
    shared_documents = cursor.fetchall()
    connection.close()
    st.divider()

    st.subheader("My Documents")
    st.write(
        "View your uploaded documents and their security status."
    )
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT document_id, original_filename,
               encrypted_file_path, uploaded_at,
               digital_signature, document_hash
        FROM documents
        WHERE owner_id = ?
        ORDER BY uploaded_at DESC
        """,
        (user_id,)
    )
    my_documents = cursor.fetchall()
    connection.close()
    if my_documents:
        for document in my_documents:
            document_id, filename, encrypted_path, uploaded_at, signature, document_hash = document
            with st.expander(filename):
                st.write("**Document ID:**", document_id)
                st.write("**Uploaded at:**", uploaded_at)
                if Path(encrypted_path).exists():
                    st.success("Encryption status: Encrypted")
                else:
                    st.error("Encrypted document file not found.")
                if signature and document_hash:
                    st.success("Digital signature: Signed")
                    if st.button("Verify Signature", key=f"verify_{document_id}"):
                        try:
                            # Retrieves the protected AES key from the database
                            connection = get_connection()
                            cursor = connection.cursor()
                            cursor.execute(
                                """
                                SELECT ephemeral_public_key, salt, nonce, protected_aes_key
                                FROM document_keys
                                WHERE document_id = ? AND recipient_id = ?
                                """,
                                (document_id, user_id)
                            )
                            key_record = cursor.fetchone()
                            connection.close()
                            if key_record is None:
                                st.error("Protected document key not found.")
                            else:
                                ephemeral_public_key, salt, nonce, protected_aes_key = key_record
                                sharing_data = {
                                    "exchange_data": {
                                        "ephemeral_public_key": ephemeral_public_key,
                                        "salt": salt
                                    },
                                    "protected_key": {
                                        "nonce": nonce,
                                        "wrapped_key": protected_aes_key
                                    }
                                }
                                aes_key = recover_recipient_aes_key(
                                    sharing_data,
                                    st.session_state.private_key,
                                    user_id,
                                    user_id,
                                    document_id
                                )
                                decrypted_path = Path("decrypted_documents") / f"{document_id}.tmp"
                                decrypted_path.parent.mkdir(parents=True, exist_ok=True)
                                try:
                                    decrypt_file(encrypted_path, decrypted_path, aes_key)
                                    document_data = decrypted_path.read_bytes()
                                finally:
                                    decrypted_path.unlink(missing_ok=True)
                                public_key = load_user_signing_public_key(user_id)  # Verifies the digital signature
                                is_valid = verify_document(
                                    document_data,
                                    signature,
                                    public_key
                                )
                                calculated_hash = calculate_document_hash(document_data)
                                hash_matches = calculated_hash == document_hash
                                if is_valid and hash_matches:
                                    st.success("Signature Valid – Document integrity verified!")
                                else:
                                    st.error("Signature Invalid – Possible tampering detected.")
                        except Exception as e:
                            from cryptography.exceptions import InvalidTag
                            if isinstance(e, InvalidTag):
                                st.error(
                                    "Document integrity check failed! "
                                    "The encrypted document may have been tampered with."
                                )
                            else:
                                st.error(f"Verification failed: {type(e).__name__}: {e}")
                else:
                    st.warning("Digital signature: Pending")
    else:
        st.info("You have not uploaded any documents yet.")
    st.divider()

    st.subheader("Share Documents")
    if not documents:
        st.info("Upload a document before sharing it.")
    elif not users:
        st.info("No other registered users are available.")
    else:
        document_options = {
            f"{filename} (ID: {document_id})": document_id
            for document_id, filename in documents
        }
        user_options = {
            f"{name} (ID: {recipient_id})": recipient_id
            for recipient_id, name in users
        }
        selected_document = st.selectbox(
            "Choose a document",
            list(document_options.keys()),
            index=None,
            placeholder="Select a document...",
            key="share_document"
        )
        selected_user = st.selectbox(
            "Choose a recipient",
            list(user_options.keys()),
            index=None,
            placeholder="Select a recipient...",
            key="share_recipient"
        )
        if st.button(
                "Share Document",
                key="share_button",
                disabled=(
                        selected_document is None or selected_user is None
                )
        ):
            document_id = document_options[selected_document]
            recipient_id = user_options[selected_user]
            connection = get_connection()
            try:
                cursor = connection.cursor()
                # Retrieves the AES key protected for the document owner
                cursor.execute(
                    """
                    SELECT ephemeral_public_key, salt, nonce, protected_aes_key
                    FROM document_keys
                    WHERE document_id = ? AND recipient_id = ?
                    """,
                    (document_id, user_id)
                )
                key_record = cursor.fetchone()
                if key_record is None:
                    st.error("Your protected document key was not found.")
                else:
                    ephemeral_public_key, salt, nonce, protected_aes_key = key_record

                    sharing_data = {
                        "exchange_data": {
                            "ephemeral_public_key": ephemeral_public_key,
                            "salt": salt
                        },
                        "protected_key": {
                            "nonce": nonce,
                            "wrapped_key": protected_aes_key
                        }
                    }
                    aes_key = recover_recipient_aes_key(
                        sharing_data,
                        private_key,
                        user_id,
                        user_id,
                        document_id
                    )
                    # Check permission and activate sharing
                    success, message = share_document(
                        user_id,
                        document_id,
                        recipient_id,
                        connection
                    )
                    if success:
                        try:
                            # Protect the AES key specifically for the recipient
                            protect_and_store_document_key(
                                aes_key,
                                user_id,
                                recipient_id,
                                document_id
                            )
                            st.session_state["flash_message"] = message
                            st.rerun()
                        except Exception:
                            revoke_access(
                                user_id,
                                document_id,
                                recipient_id,
                                connection
                            )
                            st.error(
                                "Sharing failed because the recipient's encryption key could not be stored."
                            )
                    else:
                        st.error(message)
            except Exception as e:
                st.error(f"Sharing failed: {type(e).__name__}: {e}")
            finally:
                connection.close()
    st.divider()

    st.subheader("Shared with Me")
    st.write("View documents that other users have shared with you.")
    if shared_documents:
        for document in shared_documents:
            (
                document_id,
                filename,
                encrypted_path,
                owner_id,
                owner_name
            ) = document
            with st.expander(filename):
                st.write("**Shared by:**", owner_name)
                st.write("**Document ID:**", document_id)
                if Path(encrypted_path).exists():
                    st.success("Encrypted and digitally signed document available.")
                    if st.button(
                            "Decrypt & Download",
                            key=f"decrypt_shared_{document_id}"
                    ):
                        try:
                            # Checks whether a user still has permission
                            connection = get_connection()
                            has_access = check_access(
                                user_id,
                                document_id,
                                connection
                            )
                            connection.close()
                            if not has_access:
                                st.error("You no longer have access to this document.")
                            else:
                                connection = get_connection()
                                cursor = connection.cursor()
                                cursor.execute("""
                                    SELECT ephemeral_public_key,
                                           salt,
                                           nonce,
                                           protected_aes_key
                                    FROM document_keys
                                    WHERE document_id = ?
                                      AND recipient_id = ?
                                """, (document_id, user_id))
                                key_record = cursor.fetchone()
                                connection.close()
                                if key_record is None:
                                    st.error("Your protected document key was not found.")
                                else:
                                    ephemeral_public_key, salt, nonce, protected_aes_key = key_record
                                    sharing_data = {
                                        "exchange_data": {
                                            "ephemeral_public_key": ephemeral_public_key,
                                            "salt": salt
                                        },
                                        "protected_key": {
                                            "nonce": nonce,
                                            "wrapped_key": protected_aes_key
                                        }
                                    }
                                    aes_key = recover_recipient_aes_key(
                                        sharing_data,
                                        private_key,
                                        owner_id,
                                        user_id,
                                        document_id
                                    )
                                    decrypted_folder = Path("decrypted_documents")
                                    decrypted_folder.mkdir(exist_ok=True)
                                    decrypted_path = (
                                            decrypted_folder / f"{document_id}_{filename}"
                                    )
                                    decrypt_file(
                                        encrypted_path,
                                        decrypted_path,
                                        aes_key
                                    )
                                    public_key = load_user_signing_public_key(owner_id)
                                    document_data = decrypted_path.read_bytes()
                                    connection = get_connection()
                                    cursor = connection.cursor()
                                    cursor.execute("""
                                        SELECT digital_signature, document_hash
                                        FROM documents
                                        WHERE document_id = ?
                                    """, (document_id,))
                                    signature, document_hash = cursor.fetchone()
                                    connection.close()
                                    is_valid = verify_document(
                                        document_data,
                                        signature,
                                        public_key
                                    )
                                    calculated_hash = calculate_document_hash(document_data)
                                    hash_matches = calculated_hash == document_hash
                                    if is_valid and hash_matches:
                                        st.success(
                                            "Signature Valid – Document integrity verified!"
                                        )
                                        st.download_button(
                                            "Download Decrypted Document",
                                            data=document_data,
                                            file_name=filename,
                                            key=f"download_shared_{document_id}"
                                        )
                                    else:
                                        st.error(
                                            "Signature Invalid – Document may have been tampered with."
                                        )
                                    decrypted_path.unlink(missing_ok=True) # Removes temporary decrypted copy
                        except Exception as e:
                            st.error(
                                f"Decryption failed: {type(e).__name__}: {e}"
                            )
                else:
                    st.error("Encrypted document file not found.")
    else:
        st.info("No documents have been shared with you.")
    st.divider()

    st.subheader("Manage Access Permissions")
    if active_shares:
        for document_id, filename, recipient_id, recipient in active_shares:
            with st.container(border=True):
                st.markdown(f"**{filename}**")
                st.write(f"{recipient} (User ID: {recipient_id})")
    else:
        st.info("No active sharing permissions.")

    st.subheader("Revoke Access")
    if active_shares:
        permission_options = {
            f"{filename} → {recipient}": (document_id, recipient_id)
            for document_id, filename, recipient_id, recipient in active_shares
        }
        selected_permission = st.selectbox(
            "Select access to revoke",
            list(permission_options.keys()),
            index=None,
            placeholder="Select a permission...",
            key="revoke_permission"
        )
        if st.button(
                "Revoke Access",
                key="revoke_button",
                disabled=selected_permission is None
        ):
            document_id, recipient_id = permission_options[selected_permission]
            connection = get_connection()
            success, message = revoke_access(
                user_id, document_id, recipient_id, connection
            )
            connection.close()
            if success:
                st.session_state["flash_message"] = message
                st.rerun()
            else:
                st.error(message)
    else:
        st.info("No active sharing permissions to revoke.")
    st.divider()

    st.caption(
        "Secure Multi-User Document Sharing | "
        "Encryption • Digital Signatures • Access Control"
    )
