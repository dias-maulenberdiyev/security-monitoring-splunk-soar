from pathlib import Path
import os

import pandas as pd
import requests


BASE_DIR = Path(__file__).resolve().parent

RESULTS_FILE = (
    BASE_DIR
    / "results"
    / "evaluation_scored.csv"
)

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


if not SPLUNK_HEC_TOKEN:
    raise RuntimeError(
        "SPLUNK_HEC_TOKEN environment variable is not set."
    )


results_df = pd.read_csv(RESULTS_FILE)


for _, row in results_df.iterrows():

    event = {
        "event_type": "ml_anomaly_result",
        "simulation_run": "evaluation_v1",
        "model": "isolation_forest",
        "source_ip": row["source_ip"],
        "total_requests": int(row["total_requests"]),
        "failed_login_ratio": float(
            row["failed_login_ratio"]
        ),
        "admin_ratio": float(row["admin_ratio"]),
        "unique_paths": int(row["unique_paths"]),
        "anomaly_score": float(row["anomaly_score"]),
        "is_anomaly": bool(row["is_anomaly"])
    }

    payload = {
        "index": "security_lab",
        "sourcetype": "securitylab:ml",
        "event": event
    }

    response = requests.post(
        SPLUNK_HEC_URL,
        headers={
            "Authorization":
                f"Splunk {SPLUNK_HEC_TOKEN}"
        },
        json=payload,
        verify=False,
        timeout=5
    )

    response.raise_for_status()

    print(
        row["source_ip"],
        row["anomaly_score"],
        row["is_anomaly"]
    )


print("ML results sent to Splunk.")