import streamlit as st
from db import create_tables
from auth import register_user, login_user
from dashboard import show_dashboard

create_tables()

st.set_page_config(
    page_title="Secure Multi-User Document Sharing",
    layout="centered"
)

# Initialise session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "username" not in st.session_state:
    st.session_state.username = None
if "private_key" not in st.session_state:
    st.session_state.private_key = None
if "signing_private_key" not in st.session_state:
    st.session_state.signing_private_key = None

st.markdown(
    "<h1 style='text-align: center;'> Secure Multi-User Document Sharing</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align: center;'>Protect your documents with encryption, "
    "verify their authenticity with digital signatures, and manage who can access them.</p>",
    unsafe_allow_html=True
)

if not st.session_state.logged_in:
    login_tab, register_tab = st.tabs(["Login", "Register"])
    with login_tab:
        st.subheader("Welcome Back")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input(
                "Password",
                type="password"
            )
            login_button = st.form_submit_button("Login")
        if login_button:
            success, message, user_id, private_key, signing_private_key = login_user(
                username, password
            )
            if success:
                st.session_state.logged_in = True
                st.session_state.user_id = user_id
                st.session_state.username = username
                st.session_state.private_key = private_key
                st.session_state.signing_private_key = signing_private_key
                st.success(message)
                st.rerun()
            else:
                st.error(message)
    with register_tab:
        st.subheader("Create an Account")
        with st.form("register_form"):
            new_username = st.text_input("Choose a username")
            new_password = st.text_input(
                "Choose a password",
                type="password"
            )
            confirm_password = st.text_input(
                "Confirm password",
                type="password"
            )
            register_button = st.form_submit_button("Register")
        if register_button:
            if new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                success, message = register_user(
                    new_username,
                    new_password
                )
                if success:
                    st.success(message)
                else:
                    st.error(message)
else:
    show_dashboard(
        st.session_state.username,
        st.session_state.user_id,
        st.session_state.private_key
    )
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.private_key = None
        st.session_state.signing_private_key = None
        st.rerun()
