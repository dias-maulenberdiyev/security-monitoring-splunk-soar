from pathlib import Path
import json
import os

import pandas as pd
import requests


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

RESULTS_FILE = (
    PROJECT_DIR
    / "ml"
    / "results"
    / "evaluation_scored.csv"
)

FEED_FILE = BASE_DIR / "lab_ioc_feed.json"

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


# Load ML results
results_df = pd.read_csv(RESULTS_FILE)

# Keep only anomalies
anomalies_df = results_df[
    results_df["is_anomaly"]
    .astype(str)
    .str.lower()
    .eq("true")
]


# Load simulated threat-intelligence feed
with open(FEED_FILE, "r", encoding="utf-8") as file:
    threat_feed = json.load(file)


for _, row in anomalies_df.iterrows():

    ip = row["source_ip"]

    intel = threat_feed.get(
        ip,
        {
            "reputation": "unknown",
            "threat_score": 0,
            "category": "unknown",
            "confidence": 0
        }
    )

    event = {
        "event_type": "threat_intel_enrichment",
        "simulation_run": "evaluation_v1",

        "source_ip": ip,

        "ml_model": "isolation_forest",
        "anomaly_score": float(
            row["anomaly_score"]
        ),

        "ti_provider": "lab_simulated_feed",
        "reputation": intel["reputation"],
        "threat_score": intel["threat_score"],
        "threat_category": intel["category"],
        "confidence": intel["confidence"]
    }

    payload = {
        "index": "security_lab",
        "sourcetype": "securitylab:threatintel",
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
        ip,
        intel["reputation"],
        intel["threat_score"],
        intel["category"]
    )


print("Threat-intelligence enrichment sent to Splunk.")