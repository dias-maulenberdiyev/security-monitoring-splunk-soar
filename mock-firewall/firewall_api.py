from flask import Flask, request, jsonify
from datetime import datetime, UTC
from pathlib import Path
import ipaddress
import json


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DENYLIST_FILE = BASE_DIR / "denylist.json"


def load_denylist():
    if not DENYLIST_FILE.exists():
        return []

    with open(DENYLIST_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_denylist(entries):
    with open(DENYLIST_FILE, "w", encoding="utf-8") as file:
        json.dump(entries, file, indent=2)


@app.route("/blocked-ips", methods=["GET"])
def get_blocked_ips():
    return jsonify(load_denylist())


@app.route("/block", methods=["POST"])
def block_ip():
    data = request.get_json(silent=True) or {}

    source_ip = data.get("source_ip")
    reason = data.get("reason", "unspecified")

    if not source_ip:
        return jsonify({
            "status": "error",
            "message": "source_ip is required"
        }), 400

    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return jsonify({
            "status": "error",
            "message": "invalid IP address"
        }), 400

    denylist = load_denylist()

    for entry in denylist:
        if entry["source_ip"] == source_ip:
            return jsonify({
                "status": "already_blocked",
                "source_ip": source_ip
            })

    entry = {
        "source_ip": source_ip,
        "reason": reason,
        "blocked_at": datetime.now(UTC).isoformat(),
        "simulation_only": True
    }

    denylist.append(entry)
    save_denylist(denylist)

    return jsonify({
        "status": "blocked",
        "source_ip": source_ip,
        "simulation_only": True
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )