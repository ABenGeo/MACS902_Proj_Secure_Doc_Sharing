import streamlit as st

def show_dashboard(username):
    st.markdown(
        f"<h2 style='font-weight: 700;'>"
        f"Welcome, {username}!</h2>",
        unsafe_allow_html=True
    )
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
    st.divider()

    st.subheader("My Documents")
    st.write(
        "View your uploaded documents and their security status."
    )
    st.info("Your uploaded documents will appear here.")
    st.divider()

    st.subheader("Sharing & Access Management")
    st.write(
        "Manage who can access your documents and control their permissions."
    )
    with st.expander("Share Documents"):
        st.write(
            "Select a document and choose registered users "
            "to share it with."
        )
    with st.expander("Manage Access Permissions"):
        st.write(
            "View users who have access to your documents "
            "and manage their permissions."
        )
    with st.expander("Revoke Access"):
        st.write(
            "Remove a user's access to a previously shared document."
        )
    st.divider()

    st.caption(
        "Secure Multi-User Document Sharing | "
        "Encryption • Digital Signatures • Access Control"
    )