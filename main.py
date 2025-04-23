import streamlit as st
import hashlib
import time
import json
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

DATA_FILE = 'secure_data.json'
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Initialize session states
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = 0
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lock_out_time" not in st.session_state:
    st.session_state.lock_out_time = 0

# Load and save functions
def load_data():
    if os.path.exists(DATA_FILE) and os.path.getsize(DATA_FILE) > 0:
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Crypto Functions
def generate_key(password):
    key = pbkdf2_hmac("sha256", password.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(key, text):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load data
stored_data = load_data()

# UI
st.title("🔐 Secure Data Encryption System")

# Logout button
if st.session_state.authenticated_user:
    st.markdown(f"👋 Welcome, **{st.session_state.authenticated_user}**")
    if st.button("🔓 Logout"):
        st.session_state.authenticated_user = 0
        st.success("✅ Logged out successfully!")
        st.stop()

menu = ["Home", "Register", "Login", "Store DATA", "Retrieve DATA"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("Welcome to 🔐 My Secure Data Encryption System using Streamlit!")
    st.markdown("""
    **Features:**
    - Users can **store data** with a unique passkey.
    - Users can **decrypt data** by providing the correct passkey.
    - Multiple **failed attempts** will result in a **lockout**, requiring reauthorization.
    - This system operates entirely **in memory** using a local JSON file — no external databases involved.
    
    💡 Ideal for secure mini-projects and encryption learning!
    """)

# Register
elif choice == "Register":
    st.subheader("🔐 Register New User")

    new_user = st.text_input("Enter Username")
    new_pass = st.text_input("Enter Password", type="password")
    confirm_pass = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if new_pass != confirm_pass:
            st.error("❌ Passwords do not match!")
        elif new_user in stored_data:
            st.warning("⚠️ Username already exists. Try another one.")
        else:
            hashed_pass = hash_password(new_pass)
            stored_data[new_user] = {"password": hashed_pass, "data": []}  # ✅ data is list now
            save_data(stored_data)
            st.success("✅ Registration Successful! You can now store data.")

# Login
elif choice == "Login":
    st.subheader("🔐 User Login")

    username = st.text_input("Enter Username")
    password = st.text_input("Enter Password", type="password")

    current_time = time.time()

    if st.session_state.failed_attempts >= 3:
        if current_time - st.session_state.lock_out_time < LOCKOUT_DURATION:
            remaining = int(LOCKOUT_DURATION - (current_time - st.session_state.lock_out_time))
            st.error(f"🚫 Too many failed attempts. Please wait {remaining} seconds.")
            st.stop()
        else:
            st.session_state.failed_attempts = 0

    if st.button("Login"):
        if username in stored_data:
            stored_hash = stored_data[username]["password"]
            if stored_hash == hash_password(password):
                st.session_state.authenticated_user = username
                st.success("✅ Login successful!")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lock_out_time = time.time()
                    st.error("🚫 Too many failed attempts. Account is locked for 1 minute.")
                else:
                    st.error("❌ Incorrect password.")
        else:
            st.error("❌ Username not found.")

# Store Data
elif choice == "Store DATA":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first from the Login menu.")
        if st.button("🔐 Go to Login"):
            st.experimental_set_query_params(Navigation="Login")
            st.rerun()
    else:
        st.subheader("🔐 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (Passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(passkey, data)

                # ✅ Ensure user's data is a list
                user = st.session_state.authenticated_user
                if not isinstance(stored_data[user].get("data", []), list):
                    stored_data[user]["data"] = []

                stored_data[user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("❌ Please enter both data and encryption key.")

# Retrieve Data
elif choice == "Retrieve DATA":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first from the Login menu.")
        if st.button("🔐 Go to Login"):
            st.experimental_set_query_params(Navigation="Login")
            st.rerun()
    else:
        st.subheader("🔍 Retrieve Encrypted Data")

        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            passkey = st.text_input("Enter Decryption Key (Passphrase)", type="password")
            if passkey:
                for i, item in enumerate(user_data):
                    decrypted = decrypt_text(item, passkey)
                    if decrypted:
                        st.success(f"🔓 Decrypted Data {i + 1}: {decrypted}")
                    else:
                        st.error(f"❌ Incorrect passkey for Data {i + 1}")
