#!/bin/bash

set -e

# ───── Helper Functions ─────
check_and_install_mysql() {
    if ! command -v mysql &> /dev/null; then
        echo "MySQL not found. Installing..."
        sudo apt update && sudo apt install -y mysql-server
    else
        echo "MySQL is installed."
    fi
}

check_and_install_docker() {
    if ! command -v docker &> /dev/null; then
        echo "Docker not found. Installing via APT..."

        # Install prerequisites
        sudo apt-get update
        sudo apt-get install -y ca-certificates curl gnupg

        # Add Docker’s official GPG key
        sudo install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
        sudo chmod a+r /etc/apt/keyrings/docker.asc

        # Add Docker’s apt repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
          $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
          sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

        sudo apt-get update

        # Install Docker Engine and Compose plugin
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

        echo "Docker and Docker Compose plugin installed successfully."
    else
        echo "Docker is already installed."
    fi

    # Confirm docker compose is available
    if ! docker compose version &> /dev/null; then
        echo "Docker Compose plugin not found or not working."
        echo "Please check your Docker installation or install the plugin manually."
        exit 1
    else
        echo "Docker Compose is available."
    fi
}

start_docker_services() {
    echo "Starting Kafka, Redis, etc. via Docker Compose..."

    # Save current directory
    local CURRENT_DIR
    CURRENT_DIR=$(pwd)

    # Navigate to config directory
    cd "$CURRENT_DIR/config" || { echo "Failed to enter config directory."; exit 1; }

    # Run Docker Compose (V2 syntax)
    sudo docker compose up -d

    # Return to original directory
    cd "$CURRENT_DIR"
}

setup_database() {
    echo "Setting up MySQL schema..."

    local DB_DIR="$(pwd)/database"

    if [ ! -d "$DB_DIR" ]; then
        echo "'database' directory not found."
        exit 1
    fi

    cd "$DB_DIR"

    # Just run the SQL file; it handles existence checks internally
    sudo mysql -u root -p < logwatchdatabase.sql

    echo "Database setup script executed."

    cd ..
}

setup_python_env() {
    echo "Setting up Python environment..."
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    source venv/bin/activate
    pip install -r requirements.txt
}

kafka_setup() {
    echo "Checking and setting up Kafka topics..."

    local topics=(
        failed_logins
        high_threat_protocol
        dns_alerts
        generic_log_search
        log_pattern_timeseries
    )

    for topic in "${topics[@]}"; do
        if sudo docker exec broker sh -c "/opt/kafka/bin/kafka-topics.sh --list --bootstrap-server broker:29092" | grep -w "$topic" > /dev/null; then
            echo "Topic already exists: $topic"
        else
            echo "Creating topic: $topic"
            sudo docker exec broker sh -c "/opt/kafka/bin/kafka-topics.sh --create --topic $topic --bootstrap-server broker:29092"
        fi
    done

    echo "Kafka topic setup complete."
}


run_background_workers() {
    echo "Checking and running background consumers..."

    mkdir -p logs

    for script in background_task_handler/*_consumer.py; do
        if [ ! -f "$script" ]; then
            echo "No consumer scripts found."
            break
        fi

        if pgrep -f "$script" > /dev/null; then
            echo "Consumer already running: $script"
        else
            nohup python "$script" > "logs/$(basename "$script").log" 2>&1 &
            echo "Started consumer: $script"
        fi
    done
}

run_snapshot_maker() {
    local SCRIPT="background_task_handler/sql_snapshot_maker.py"

    if [ ! -f "$SCRIPT" ]; then
        echo "Snapshot maker script not found."
        return 1
    fi

    if pgrep -f "$SCRIPT" > /dev/null; then
        echo "Snapshot maker already running."
        return
    fi

    echo "Running Kafka-to-SQL snapshot maker..."
    mkdir -p logs
    nohup python "$SCRIPT" > logs/snapshot_maker.log 2>&1 &
    echo "Snapshot maker started, logging to logs/snapshot_maker.log"
}


run_go_producer() {
    echo "Checking if Go producer is running..."

    if pgrep -f "background_task_handler/main" > /dev/null; then
        echo "Go producer already running."
        return
    fi

    local EXEC="background_task_handler/main"

    if [ ! -x "$EXEC" ]; then
        echo "Executable $EXEC not found or not executable."
        return 1
    fi

    mkdir -p logs
    nohup "$EXEC" > logs/go_producer.log 2>&1 &
    echo "Go producer started in background, logging to logs/go_producer.log"
}


start_fastapi_server() {
    if lsof -i:8000 &>/dev/null; then
        echo "FastAPI already running on port 8000."
    else
        echo "Starting FastAPI backend..."
        nohup uvicorn fastapiserver:app --reload --host 0.0.0.0 --port 8000 > logs/fastapi.log 2>&1 &
        echo "FastAPI started, logs at logs/fastapi.log"
    fi
}


start_streamlit_app() {
    if pgrep -f "streamlit run frontend.py" > /dev/null; then
        echo "Streamlit frontend already running."
    else
        echo "Launching Streamlit frontend..."
        mkdir -p logs
        nohup streamlit run frontend.py > logs/streamlit.log 2>&1 &
        echo "Streamlit started, logs at logs/streamlit.log"
    fi
}

run_all() {
    echo "==== Starting Full Application Setup ===="

    check_and_install_mysql
    check_and_install_docker
    start_docker_services
    echo "Waiting for Kafka to be ready..."
    for i in {1..20}; do
        if sudo docker exec broker sh -c "/opt/kafka/bin/kafka-topics.sh --bootstrap-server broker:29092 --list" &> /dev/null; then
            echo "Kafka is ready!"
            break
        else
            echo "Kafka not ready yet. Waiting... ($i)"
            sleep 3
        fi
    done
    kafka_setup
    setup_database
    setup_python_env
    run_background_workers
    run_snapshot_maker
    run_go_producer
    start_fastapi_server
    start_streamlit_app

    echo "==== All services initialized ===="
}

run_all