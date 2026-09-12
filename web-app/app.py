from flask import Flask, request, jsonify
import logging
import json
import requests
from datetime import datetime, UTC
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "..", "logs")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

if not SPLUNK_HEC_URL:
    raise RuntimeError(
        "SPLUNK_HEC_URL environment variable is not set."
    )

if not SPLUNK_HEC_TOKEN:
    raise RuntimeError(
        "SPLUNK_HEC_TOKEN environment variable is not set."
    )

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "security.log"),
    level=logging.INFO,
    format="%(message)s"
)

def send_to_splunk(event):
    if not SPLUNK_HEC_TOKEN:
        print("SPLUNK_HEC_TOKEN is not set")
        return

    payload = {
        "index": "security_lab",
        "sourcetype": "securitylab:json",
        "event": event
    }

    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"
    }

    try:
        response = requests.post(
            SPLUNK_HEC_URL,
            headers=headers,
            json=payload,
            verify=False,
            timeout=5
        )

        response.raise_for_status()
        print("Sent to Splunk:", response.text)

    except requests.RequestException as error:
        print("Splunk error:", error)

def write_security_log(event_type, status):
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
        "source_ip": request.headers.get(
            "X-Simulated-IP",
            request.remote_addr
        ),
        "simulation_run": request.headers.get(
            "X-Simulation-Run",
            "manual"
        ),
        "method": request.method,
        "path": request.path,
        "status": status,
        "user_agent": request.headers.get("User-Agent")
    }

    logging.info(json.dumps(event))
    send_to_splunk(event)


@app.route("/")
def home():
    write_security_log("web_request", "success")

    return jsonify({
        "message": "Security Monitoring Lab"
    })


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username == "admin" and password == "secure123":
        write_security_log("login_attempt", "success")
        return jsonify({"status": "login successful"})

    write_security_log("login_attempt", "failed")
    return jsonify({"status": "login failed"}), 401


@app.route("/admin")
def admin():
    write_security_log("admin_access", "success")
    return jsonify({
        "message": "Admin panel"
    })


if __name__ == "__main__":
    app.run(debug=True)