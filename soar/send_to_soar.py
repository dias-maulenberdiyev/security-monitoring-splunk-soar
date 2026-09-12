from pathlib import Path
import json
import os
import time

import pandas as pd
import requests
import urllib3


PROJECT_DIR = Path(__file__).resolve().parent.parent

ML_RESULTS_FILE = (
    PROJECT_DIR
    / "ml"
    / "results"
    / "evaluation_scored.csv"
)

THREAT_FEED_FILE = (
    PROJECT_DIR
    / "threat-intel"
    / "lab_ioc_feed.json"
)

SOAR_URL = os.getenv("SOAR_URL")
SOAR_TOKEN = os.getenv("SOAR_AUTH_TOKEN")

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

if not SOAR_URL:
    raise RuntimeError(
        "SOAR_URL environment variable is not set."
    )

if not SOAR_TOKEN:
    raise RuntimeError(
        "SOAR_AUTH_TOKEN environment variable is not set."
    )


HEADERS = {
    "ph-auth-token": SOAR_TOKEN,
    "Content-Type": "application/json"
}


def create_container(ip, intel, anomaly_score):
    url = f"{SOAR_URL}/rest/container"

    severity = (
        "high"
        if intel["reputation"] == "malicious"
        else "medium"
    )

    payload = {
        "name": f"Security Lab IOC - {ip}",
        "label": "events",
        "severity": severity,
        "description": (
            "Automatically created from the Security Monitoring Lab. "
            f"Isolation Forest anomaly score: {anomaly_score:.6f}. "
            f"Threat reputation: {intel['reputation']}. "
            f"Threat score: {intel['threat_score']}. "
            f"Confidence: {intel['confidence']}. "
            f"Category: {intel['category']}."
        ),
        "source_data_identifier": (
            f"api_test_v2-container-{ip}"
        )
    }

    response = requests.post(
        url,
        headers=HEADERS,
        json=payload,
        verify=False,
        timeout=10
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):
        raise RuntimeError(
            f"Container creation failed: {result}"
        )

    return result["id"]


def create_artifact(
    container_id,
    ip,
    intel,
    anomaly_score
):
    url = f"{SOAR_URL}/rest/artifact"

    severity = (
        "high"
        if intel["reputation"] == "malicious"
        else "medium"
    )

    payload = {
        "container_id": container_id,
        "name": "Enriched suspicious source IP",
        "label": "event",
        "severity": severity,
        "source_data_identifier": (
            f"api_test_v2-artifact-{ip}"
        ),

        "cef": {
            "sourceAddress": ip,

            "mlAnomaly": "true",

            "anomalyScore": str(
                round(anomaly_score, 6)
            ),

            "reputation": intel["reputation"],

            "threatScore": str(
                intel["threat_score"]
            ),

            "confidence": str(
                intel["confidence"]
            ),

            "threatCategory": intel["category"]
        },

        "cef_types": {
            "sourceAddress": ["ip"]
        },

        "run_automation": True
    }

    response = requests.post(
        url,
        headers=HEADERS,
        json=payload,
        verify=False,
        timeout=10
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("success"):
        raise RuntimeError(
            f"Artifact creation failed: {result}"
        )

    return result["id"]


def main():
    ml_df = pd.read_csv(ML_RESULTS_FILE)

    with open(
        THREAT_FEED_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        threat_feed = json.load(file)

    anomalies = ml_df[
        ml_df["is_anomaly"]
        .astype(str)
        .str.lower()
        .eq("true")
    ]

    print(
        f"Sending {len(anomalies)} "
        "anomalous IOCs to Splunk SOAR..."
    )

    for _, row in anomalies.iterrows():
        ip = row["source_ip"]
        anomaly_score = float(
            row["anomaly_score"]
        )

        intel = threat_feed.get(
            ip,
            {
                "reputation": "unknown",
                "threat_score": 0,
                "confidence": 0,
                "category": "unknown"
            }
        )

        container_id = create_container(
            ip,
            intel,
            anomaly_score
        )

        artifact_id = create_artifact(
            container_id,
            ip,
            intel,
            anomaly_score
        )

        print(
            f"{ip}: "
            f"container={container_id}, "
            f"artifact={artifact_id}, "
            f"reputation={intel['reputation']}"
        )

        time.sleep(1)

    print("SOAR ingestion complete.")


if __name__ == "__main__":
    main()