import streamlit as st
import mysql.connector
from mysql.connector import Error
import bcrypt
import json
import requests
from contextlib import contextmanager

from functions import (
    load_user_services,
    save_user_services,
    ANALYSIS_HANDLERS,
)

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
                st.write(f"🔄 `{job['service_name']}` every {job['interval_seconds']} min")
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

    if not st.session_state.service_list:
        st.info("Add at least one microservice to create a background job.")
        return

    selected_service = st.selectbox("Microservice", st.session_state.service_list)

    # Ask user if they want alert-capable analyses only
    alertable_only = st.checkbox("Show only alert-capable analyses?")

    # Filter analysis types dynamically
    available_analysis = {
        key: val for key, val in ANALYSIS_HANDLERS.items()
        if (selected_service in val["services"] or "*" in val["services"])
        and (not alertable_only or val.get("alertable", False))
    }

    if not available_analysis:
        st.warning("No available analyses for this service with selected filter.")
        return

    analysis_type_key = st.selectbox(
        "Analysis Type",
        list(available_analysis.keys()),
        format_func=lambda k: available_analysis[k]["label"]
    )

    selected_handler = available_analysis[analysis_type_key]


    # Now the form begins
    with st.form("job_form"):
        interval = st.number_input("Interval (in seconds)", min_value=5, max_value=86400, value=60, step=1)

        alert_enabled = False
        alert_channel = ""
        alert_target = ""

        if alertable_only:  # If 'Show only alert-capable analyses' is checked, automatically enable alerts
            alert_enabled = True  # Enable alerts automatically
            alert_channel = st.selectbox("Alert Channel", ["email", "slack"])
            alert_target = st.text_input("Alert Target (email or webhook)")
        elif selected_handler.get("alertable", False):  # Keep the previous behavior for non-alertable analyses
            alert_enabled = st.checkbox("Enable Alerts?")
            if alert_enabled:
                alert_channel = st.selectbox("Alert Channel", ["email", "slack"])
                alert_target = st.text_input("Alert Target (email or webhook)")

        # Optional config (for generic search)
        custom_config = {}
        if selected_handler.get("configurable"):
            field = st.text_input("Field to search within (e.g., status)", value="status")
            keyword = st.text_input("Keyword to search for", value="error")
            custom_config["field"] = field
            custom_config["keyword"] = keyword


        submit = st.form_submit_button("Create Job")

        if submit:
            conn = create_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO background_jobs (
                            username, service_name, analysis_type, interval_seconds,
                            alert_enabled, alert_channel, alert_target
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        st.session_state.username, selected_service, analysis_type_key, interval,
                        alert_enabled, alert_channel, alert_target
                    ))
                    conn.commit()
                    conn.close()
                    st.success("Background job created!")
                    st.rerun()
                except Error as e:
                    st.error(f"Error creating job: {e}")

def service_detail_ui(service_name):
    st.title(f"🔍 Logs for `{service_name}`")

    if st.button("⬅️ Back to Dashboard"):
        st.session_state.selected_service = None
        st.rerun()

    st.markdown("---")

    st.markdown("### 🔍 Select Analysis Type")

    # Find applicable analysis handlers for this service
    applicable_analyses = {
        key: cfg for key, cfg in ANALYSIS_HANDLERS.items()
        if service_name in cfg["services"] or "*" in cfg["services"]
    }

    if not applicable_analyses:
        st.info("No analysis options available for this service.")
        return

    selected_key = st.selectbox(
        "Choose an analysis",
        list(applicable_analyses.keys()),
        format_func=lambda k: applicable_analyses[k]["label"]
    )

    range_seconds = st.slider("Log Time Range (seconds)", 60, 3600, 360)

    threshold = None
    custom_config = {}

    # Handle config per analysis type
    if selected_key == "failed_logins":
        threshold = st.number_input("Login Failure Threshold", min_value=1, value=3)
    elif selected_key == "generic_log_search":
        field = st.text_input("Field to Search", value="status")
        keyword = st.text_input("Keyword", value="error")
        custom_config["field"] = field
        custom_config["keyword"] = keyword

    if st.button("Run Analysis"):
        with st.spinner("Contacting server..."):
            try:
                payload = {
                    "service_name": service_name,
                    "range_seconds": range_seconds
                }
                if threshold:
                    payload["threshold"] = threshold
                if selected_key == "generic_log_search":
                    payload.update(custom_config)

                response = requests.post(
                    f"http://localhost:8000/manual-analyze/{selected_key}",
                    json=payload
                )

                if response.status_code != 200:
                    st.error(f"Server error: {response.status_code} - {response.text}")
                    return

                data = response.json()

                if "error" in data:
                    st.error(data["error"])
                elif "message" in data:
                    st.info(data["message"])
                else:
                    result = data.get("result", {})
                    st.markdown(f"## 📊 {applicable_analyses[selected_key]['label']}")
                    for key, val in result.items():
                        st.markdown(f"### {key}")
                        if isinstance(val, list):
                            if val and isinstance(val[0], dict):
                                with st.expander(f"View {len(val)} items"):
                                    for item in val:
                                        st.json(item)
                            elif val:
                                st.write(", ".join(str(x) for x in val))
                            else:
                                st.success("No relevant data.")
                        else:
                            st.write(val)

            except Exception as e:
                st.error(f"Request failed: {e}")



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