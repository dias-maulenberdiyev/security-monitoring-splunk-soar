# Security Monitoring & Automated Incident Response with Splunk SOAR

An end-to-end cybersecurity lab that demonstrates security telemetry collection, rule-based detection, anomaly detection with machine learning, threat-intelligence enrichment, SOAR orchestration, and simulated automated containment.

The project was originally based on the concept of my BSc group project and was independently rebuilt end-to-end as a clean portfolio implementation.

## Architecture

```mermaid
flowchart LR
    A[Flask Web Application] --> B[Structured JSON Security Logs]
    B --> C[Splunk Cloud]
    C --> D[SPL Detection Rules]
    C --> E[Feature Engineering]
    E --> F[Isolation Forest]
    F --> G[ML Anomaly Results]
    G --> C
    G --> H[Threat Intelligence Enrichment]
    H --> C
    H --> I[Splunk SOAR]
    I --> J{Decision Logic}
    J -->|High-confidence malicious IOC| K[Mock Firewall API]
    J -->|Insufficient confidence| L[No Automatic Containment]
    K --> M[Simulated Deny List]
Project Workflow
A Flask application generates structured security events such as page requests and failed login attempts.
Events are sent to Splunk Cloud through HTTP Event Collector (HEC).
SPL detection rules identify suspicious behavior such as repeated failed authentication attempts.
A traffic generator creates controlled normal and anomalous traffic using documentation-only IP ranges.
Splunk events are aggregated into behavioral features for each source IP.
An Isolation Forest model is trained only on the normal baseline dataset.
Evaluation profiles are scored and anomaly results are sent back to Splunk.
Anomalous IPs are enriched using a simulated threat-intelligence feed.
Enriched artifacts are submitted to Splunk SOAR through its REST API.
A SOAR playbook evaluates the artifact and performs simulated containment through a mock firewall REST API.
Security Monitoring

Security events contain fields including:

timestamp
event type
source IP
HTTP method
request path
status
user agent
simulation run

Example brute-force detection logic:
index=security_lab event_type="login_attempt" status="failed"
| bin _time span=5m
| stats count by _time source_ip
| where count >= 5

The corresponding Splunk alert detects five or more failed login attempts from the same IP within five minutes.

Machine Learning

The anomaly-detection component uses IsolationForest from scikit-learn.

The model is trained only on normal baseline behavior using the following features:

total requests
failed login ratio
admin request ratio
number of unique paths

The evaluation dataset contains 30 simulated normal profiles and three deliberately injected anomalous profiles:

repeated failed authentication attempts
unusually high /admin access
unusually high request volume

A custom anomaly score is derived from the Isolation Forest output, where a higher score represents more unusual behavior.

Controlled Evaluation Result

In the controlled evaluation dataset:

3 of 3 injected anomalous profiles were identified
0 of 30 simulated normal profiles were flagged

These results describe only the controlled synthetic evaluation and should not be interpreted as general real-world detection accuracy.

Threat Intelligence

The anomalous addresses use IANA documentation networks such as 203.0.113.0/24.

Because these addresses are not real malicious infrastructure, the project uses an explicitly simulated threat-intelligence feed rather than presenting external reputation results as genuine.

The enrichment stage adds:

reputation
threat score
confidence
threat category
threat-intelligence provider
Splunk SOAR

Splunk SOAR receives enriched anomalous IP artifacts through its REST API.

The automated playbook evaluates four conditions:
mlAnomaly == true
reputation == malicious
threatScore >= 85
confidence >= 80

Only when all conditions are satisfied is automated containment executed.

For the controlled test:
203.0.113.50
met the containment criteria.

The remaining anomalous profiles did not satisfy the full decision policy and therefore were not automatically blocked.
Simulated Containment

Containment is implemented using a local mock firewall REST API.

Splunk SOAR sends a block request to:
POST /block

The mock firewall records the IP address, reason, timestamp, and:
"simulation_only": true

This design demonstrates the automated response workflow without modifying a real production firewall.

Evidence
SOAR Playbook

Automated Decision Logic

Enriched SOAR Artifact

Simulated Containment Result

Project Structure
security-monitoring-splunk-soar/
├── web-app/
│   └── app.py
├── traffic-generator/
│   └── generate_traffic.py
├── ml/
│   ├── data/
│   ├── results/
│   ├── train_isolation_forest.py
│   └── send_results_to_splunk.py
├── threat-intel/
│   ├── lab_ioc_feed.json
│   └── enrich_iocs.py
├── soar/
│   └── send_to_soar.py
├── mock-firewall/
│   └── firewall_api.py
├── screenshots/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md

Installation

Install the Python dependencies:
pip install -r requirements.txt

Configure environment variables before running integrations.

Required variables:
SPLUNK_HEC_URL
SPLUNK_HEC_TOKEN
SOAR_URL
SOAR_AUTH_TOKEN

See .env.example for the expected format.

Running the Lab

Start the Flask application:
python web-app/app.py

Generate baseline traffic:
python traffic-generator/generate_traffic.py baseline

Generate evaluation traffic:
python traffic-generator/generate_traffic.py evaluation

Train and evaluate the Isolation Forest:
python ml/train_isolation_forest.py

Send ML results to Splunk:
python ml/send_results_to_splunk.py

Perform threat-intelligence enrichment:
python threat-intel/enrich_iocs.py

Send enriched artifacts to Splunk SOAR:
python soar/send_to_soar.py

Security Notes
Credentials and API tokens are loaded from environment variables.
Private keys and .env files are excluded through .gitignore.
Synthetic documentation IP ranges are used for traffic simulation.
Threat intelligence and firewall containment are explicitly simulated.
TLS certificate verification may be disabled in parts of the lab because of trial/self-signed certificates and should not be used that way in production environments.
Technologies
Python
Flask
Splunk Cloud
Splunk SPL
Splunk HTTP Event Collector
Splunk SOAR
REST APIs
pandas
scikit-learn
Isolation Forest
AWS EC2
JSON
Purpose

This project demonstrates how detection engineering, behavioral analytics, threat intelligence, SOAR orchestration, and automated incident response can be integrated into a single security monitoring workflow.
