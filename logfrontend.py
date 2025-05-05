import streamlit as st
import mysql.connector
from mysql.connector import Error
from functions import fetch_logs_for_service
import bcrypt
import json
from functions import (
    analyze_firewall_logs,
    analyze_auth_service_logs,
    alert_by_domain,
    alert_by_reason,
    load_user_services,
    save_user_services,
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

        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            st.session_state.username = username
            st.session_state.service_list = load_user_services(username, conn)
            return True
    except Error as e:
        st.error(f"Authentication error: {e}")
    finally:
        conn.close()
    return False


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

def register_user(username, password):
    conn = create_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        
        st.session_state.username = username
        st.session_state.service_list = []
        save_user_services(username, st.session_state.service_list, conn)
        conn.close()

        return True
    except Error as e:
        st.error(f"Registration error: {e}")
        return False

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


# ---------------- Dashboard UI ---------------- #
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
            conn = create_connection()
            if conn:
                try:
                    save_user_services(st.session_state.username, st.session_state.service_list, conn)
                finally:
                    conn.close()
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    st.markdown("---")
    st.subheader("Your Microservices")

    # ---------------- Existing Microservice UI ----------------

    for service in st.session_state.service_list:
        col1, col2, col3 = st.columns([4, 1, 1])
        with col1:
            st.write(service)
        with col2:
            if st.button("View", key=f"view-{service}"):
                st.session_state.selected_service = service
                st.rerun()
        with col3:
            if st.button("❌", key=f"del-{service}"):
                st.session_state.service_list.remove(service)
                st.success(f"Removed {service}")
                st.rerun()

    st.markdown("---")
    st.subheader("⚙️ Manage Background Jobs")

    # ---------------- Fetch Background Jobs ----------------

    jobs = []
    conn = create_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM background_jobs WHERE username = %s", (st.session_state.username,))
            jobs = cursor.fetchall()
            conn.close()
        except Error as e:
            st.error(f"Error fetching background jobs: {e}")

    # ---------------- Display Background Jobs ----------------

    if jobs:
        for job in jobs:
            col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
            with col1:
                st.write(f"🔄 `{job['service_name']}` every {job['interval_minutes']} min")
            with col2:
                st.write(f"Alert: {'✅' if job['alert_enabled'] else '❌'}")
            with col3:
                st.write(f"Enabled: {'🟢' if job['enabled'] else '🔴'}")
            with col4:
                if st.button("🗑️", key=f"del-{job['id']}"):
                    conn = create_connection()
                    if conn:
                        try:
                            cur = conn.cursor()
                            cur.execute("DELETE FROM background_jobs WHERE id = %s", (job["id"],))
                            conn.commit()
                            conn.close()
                            st.success("Deleted job.")
                            st.rerun()
                        except Error as e:
                            st.error(f"Error deleting job: {e}")

    # ---------------- Create Background Job Form ----------------

    st.markdown("### ➕ Create New Background Job")

    alert_enabled = st.checkbox("Enable Alerts")

    with st.form("job_form"):
        selected_service = st.selectbox("Microservice", st.session_state.service_list)
        analysis_type = st.selectbox("Analysis Type", ["failed_logins", "high_threat_protocol", "dns_alerts"])
        interval = st.selectbox("Interval (minutes)", [5, 15, 30, 60])

        alert_channel = st.selectbox("Alert Channel", ["email", "slack"]) if alert_enabled else ""
        alert_target = st.text_input("Alert Target") if alert_enabled else ""

        submit = st.form_submit_button("Create Job")

        if submit:
            conn = create_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO background_jobs (
                            username, service_name, analysis_type, interval_minutes, 
                            alert_enabled, alert_channel, alert_target
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        st.session_state.username, selected_service, analysis_type, interval,
                        alert_enabled, alert_channel, alert_target
                    ))
                    conn.commit()
                    conn.close()
                    st.success("Background job created!")
                    st.rerun()
                except Error as e:
                    st.error(f"Error creating job: {e}")

# ---------------- Service Detail UI ---------------- #
def service_detail_ui(service_name):
    st.title(f"🔍 Logs for `{service_name}`")

    if st.button("⬅️ Back to Dashboard"):
        st.session_state.selected_service = None
        st.rerun()

    st.markdown("---")

    with st.spinner("Fetching logs from Graylog..."):
        try:
            service_logs = fetch_logs_for_service(service_name, range_minutes=360)
        except Exception as e:
            st.error(str(e))
            return

    if not service_logs:
        st.info(f"No logs found for `{service_name}`.")
        return

    # AUTH service analysis
    if "auth" in service_name.lower():
        result = analyze_auth_service_logs(service_logs)

        st.subheader("🚨 Users with Excessive Failures")
        if result["Users with Excessive Failures"]:
            for user, count in result["Users with Excessive Failures"]:
                st.warning(f"{user} → {count} failed attempts")
                with st.expander(f"View error logs for {user}"):
                    user_logs = result["Error Logs By User"].get(user, [])
                    for log in user_logs:
                        st.json(log)
        else:
            st.success("No users exceeded the failure threshold.")

        st.subheader("📊 Common Failure Reasons")
        if result["Common Failure Reasons"]:
            for reason, freq in result["Common Failure Reasons"]:
                st.info(f"'{reason}' occurred {freq} times")
                with st.expander(f"View logs for reason: '{reason}'"):
                    reason_logs = result["Error Logs By Reason"].get(reason, [])
                    for log in reason_logs:
                        st.json(log)
        else:
            st.write("No failure reasons found.")

    # FIREWALL service analysis
    elif "firewall" in service_name.lower():
        result = analyze_firewall_logs(service_logs)

        st.subheader("🛡️ Firewall Threat Summary")
        st.write(f"**Low Threat Logs Count:** {result['Low Threat Logs Count']}")
        st.write(f"**Medium Threat Logs Count:** {result['Medium Threat Logs Count']}")
        st.write(f"**Most Common High Threat Protocol:** {result['Most Common High Threat Protocol']}")

        st.markdown("### 🔸 Low Threat Logs")
        if result["low_threat_logs"]:
            with st.expander(f"View {len(result['low_threat_logs'])} Low Threat Logs"):
                for log in result["low_threat_logs"]:
                    st.json(log)
        else:
            st.success("No low threat logs.")

        st.markdown("### 🔸 Medium Threat Logs")
        if result["med_threat_logs"]:
            with st.expander(f"View {len(result['med_threat_logs'])} Medium Threat Logs"):
                for log in result["med_threat_logs"]:
                    st.json(log)
        else:
            st.success("No medium threat logs.")

        st.markdown("### 🔸 High Threat Logs")
        if result["high_threat_logs"]:
            with st.expander(f"View {len(result['high_threat_logs'])} High Threat Logs"):
                for log in result["high_threat_logs"]:
                    st.json(log)
        else:
            st.success("No high threat logs.")

    # DNS service analysis
    elif "dns" in service_name.lower():
        st.subheader("🛑 DNS Alert Reports")

        domain_alerts = alert_by_domain(service_logs)
        reason_alerts = alert_by_reason(service_logs)

        st.markdown("### ⚠️ Domain Alerts")
        if domain_alerts:
            for alert in domain_alerts:
                st.error(alert["message"])
                with st.expander(f"View logs for domain: '{alert['domain']}'"):
                    for log in alert["logs"]:
                        st.json(log)
        else:
            st.success("No domain alerts.")

        st.markdown("### ⚠️ Reason Alerts")
        if reason_alerts:
            for alert in reason_alerts:
                st.error(alert["message"])
                with st.expander(f"View logs for reason: '{alert['reason']}'"):
                    for log in alert["logs"]:
                        st.json(log)
        else:
            st.success("No reason alerts.")

    else:
        st.write(f"No specific analysis defined for `{service_name}`.")
        st.json(service_logs[:5])

# ---------------- Navigation Logic ---------------- #
if 'step' not in st.session_state:
    st.session_state.step = 'login'
if 'selected_service' in st.session_state and st.session_state.selected_service:
    service_detail_ui(st.session_state.selected_service)
elif st.session_state.step == 'login':
    login_ui()
elif st.session_state.step == 'register':
    register_ui()
elif st.session_state.step == 'dashboard':
    dashboard_ui()