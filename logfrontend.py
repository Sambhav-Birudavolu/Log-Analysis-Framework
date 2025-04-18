import streamlit as st
import mysql.connector
from mysql.connector import Error
import bcrypt
import json
from functions import (
    analyze_firewall_logs,
    analyze_auth_service_logs,
    alert_by_domain,
    alert_by_reason,
)
from requests.auth import HTTPBasicAuth
import requests


# Set page configuration
st.set_page_config(
    page_title="Log Analysis Portal",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)
st.markdown(
    """
    <style>
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        font-size: 16px;
        border-radius: 12px;
    }
    </style>
    """, 
    unsafe_allow_html=True
)

# ---------------- Database Connection ---------------- #
def create_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='rootpwd',
            database='hpelog'
        )
        if conn.is_connected():
            return conn
    except Error as e:
        st.error(f"Database connection error: {e}")
    return None

# ---------------- User Authentication ---------------- #
def authenticate_user(username, password):
    conn = create_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            st.session_state.username = username
            load_user_services(username)
            return True
    except Error as e:
        st.error(f"Authentication error: {e}")
    return False

# ---------------- Check if User Exists ---------------- #
def user_exists(username):
    conn = create_connection()
    if not conn:
        return False
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()
        return bool(user)
    except Error as e:
        st.error(f"Error checking user: {e}")
        return False

# ---------------- Register New User ---------------- #
def register_user(username, password):
    conn = create_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        conn.close()
        st.session_state.username = username
        st.session_state.service_list = []
        save_user_services(username)

        return True
    except Error as e:
        st.error(f"Registration error: {e}")
        return False

# ---------------- Login UI ---------------- #
def login_ui():
    st.title('Login')

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button('Login'):
        if not username or not password:
            st.error("Please enter both username and password.")
        elif authenticate_user(username, password):
            st.success("Login successful!")
            st.session_state.step = 'dashboard'
            st.rerun()
        else:
            st.error("Invalid username or password.")

    if st.button("Don't have an account? Register"):
        st.session_state.step = 'register'
        st.rerun()

# ---------------- Register UI ---------------- #
def register_ui():
    st.title('Register New Account')

    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    if st.button('Register'):
        if not username or not password:
            st.error("Please fill out both fields.")
        elif user_exists(username):
            st.error("Username already exists.")
        else:
            if register_user(username, password):
                st.success("Registration successful!")
                st.session_state.step = 'dashboard'
                st.rerun()

    if st.button('Already have an account? Login'):
        st.session_state.step = 'login'
        st.rerun()


# Load services from DB into session
def load_user_services(username):
    conn = create_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT services FROM user_services WHERE username = %s", (username,))
            row = cursor.fetchone()
            conn.close()
            if row and row['services']:
                st.session_state.service_list = json.loads(row['services'])
            else:
                st.session_state.service_list = []
        except Error as e:
            st.error(f"Error loading services: {e}")

# Save services from session to DB
def save_user_services(username):
    conn = create_connection()
    if conn:
        try:
            cursor = conn.cursor()
            services_json = json.dumps(st.session_state.service_list)

            # UPSERT (insert or update)
            cursor.execute("""
                INSERT INTO user_services (username, services) 
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE services = VALUES(services)
            """, (username, services_json))
            conn.commit()
            conn.close()
        except Error as e:
            st.error(f"Error saving services: {e}")


def dashboard_ui():
    st.title(f"Welcome, {st.session_state.username} 👋")

    new_service = st.text_input("Enter a microservice name")

    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Add Microservice"):
            if new_service:
                if new_service not in st.session_state.service_list:
                    st.session_state.service_list.append(new_service)
                    st.success(f"Added {new_service}")
                else:
                    st.warning("Service already in the list.")
            else:
                st.error("Enter a name first.")

    with col2:
        if st.button("Logout"):
            save_user_services(st.session_state.username)
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    st.markdown("---")
    st.subheader("Your Microservices")

    for service in st.session_state.service_list:
        col1, col2 = st.columns([4, 1])
        with col1:
            st.button(service, key=f"btn-{service}")
        with col2:
            if st.button("❌", key=f"del-{service}"):
                st.session_state.service_list.remove(service)
                st.success(f"Removed {service}")
                st.rerun()

    st.markdown("---")
    st.subheader("📊 Log Analysis")

    if st.button("Fetch & Analyze Logs"):
        with st.spinner("Fetching logs from Graylog..."):

            # Graylog API setup
            graylog_url = "http://localhost:9000/api/search/universal/relative"
            auth = HTTPBasicAuth("admin", "1q2w3e4r5t6y7u8i9o0p")
            headers = {
                "Accept": "application/json",
                "X-Requested-By": "streamlit"
            }
            params = {
                "query": "status:ERROR",
                "range": 360,
                "decorate": "true"
            }

            response = requests.get(graylog_url, auth=auth, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json().get("messages", [])
                
                # Dynamic grouping of logs by user-defined services
                service_logs = {svc: [] for svc in st.session_state.service_list}
                for entry in data:
                    msg = entry.get("message", {})
                    service = msg.get("service")
                    if service in st.session_state.service_list:
                        service_logs[service].append(msg)

                # Analyze logs per service
                for service, logs in service_logs.items():
                    if not logs:
                        st.info(f"No logs for `{service}`.")
                        continue

                    st.markdown(f"### 🔹 Logs for `{service}`")

                    # Dynamic detection of analysis type based on service name
                    if "auth" in service.lower():
                        result = analyze_auth_service_logs(logs)
                        st.write("**Users with Excessive Failures:**")
                        for user, count in result["Users with Excessive Failures"]:
                            st.warning(f"{user} → {count} failed attempts")
                        st.write("**Common Failure Reasons:**")
                        for reason, freq in result["Common Failure Reasons"]:
                            st.info(f"'{reason}' occurred {freq} times")

                    elif "firewall" in service.lower():
                        result = analyze_firewall_logs(logs)
                        for k, v in result.items():
                            st.write(f"**{k}:** {v}")

                    elif "dns" in service.lower():
                        domain_alerts = alert_by_domain(logs)
                        reason_alerts = alert_by_reason(logs)
                        for alert in domain_alerts + reason_alerts:
                            st.error(alert)

                    else:
                        st.write(f"No specific analysis defined for `{service}`.")
                        st.json(logs[:3])  # Just show a few raw logs
            else:
                st.error(f"Failed to fetch logs: {response.status_code}")
                st.text(response.text)




# ---------------- Navigation Logic ---------------- #
if 'step' not in st.session_state:
    st.session_state.step = 'login'

if st.session_state.step == 'login':
    login_ui()
elif st.session_state.step == 'register':
    register_ui()
elif st.session_state.step == 'dashboard':
    dashboard_ui()