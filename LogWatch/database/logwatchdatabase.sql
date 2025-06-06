create database if not exists hpelog;
use hpelog;

CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_services (
    username VARCHAR(50) PRIMARY KEY,
    services TEXT
);

CREATE TABLE IF NOT EXISTS background_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    service_name VARCHAR(255),
    analysis_type VARCHAR(255),
    interval_seconds INT,
    query TEXT,                      
    alert_enabled BOOLEAN DEFAULT FALSE,
    alert_channel VARCHAR(50),
    alert_target VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    last_run DATETIME(3) DEFAULT NULL,
    threshold INT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS job_results (
    job_id INT,
    timestamp DATETIME(3),  -- when this snapshot was written
    result_json JSON,
    PRIMARY KEY (job_id)
);

CREATE USER IF NOT EXISTS 'appuser'@'localhost' IDENTIFIED BY 'rootpwd';
GRANT ALL PRIVILEGES ON hpelog.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;
