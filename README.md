
# SentinelLite 🛡️

**Security Monitoring & Threat Detection Dashboard**

SentinelLite is a Python-based defensive cybersecurity project that
analyzes synthetic authentication logs, detects repeated failed login
attempts, and presents findings in an interactive Streamlit dashboard.

## Features

- Authentication log parsing and validation
- Rule-based detection of repeated failed logins
- Configurable attempt threshold and time window
- Security metrics and event distribution chart
- Filterable authentication event explorer
- JSON security report export
- Automated tests using pytest

## Technology Stack

- Python
- Streamlit
- Pandas
- Pytest

## Run Locally

1. Clone this repository.
2. Create and activate a Python virtual environment.
3. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   python -m pip install pytest
   ```

4. Launch the dashboard:

   ```bash
   streamlit run app.py
   ```

5. Run the tests:

   ```bash
   python -m pytest -v
   ```

## Detection Rule

**AUTH-001 — Repeated Failed Logins**

The detector raises a high-severity alert when failed login events from
the same source IP reach the configured threshold within the selected
time window.

## Sample Data

The included authentication logs are synthetic and intended for
demonstration and testing. The project does not establish that an alert
represents a confirmed attack.

## Project Structure

```text
sentinellite/
├── app.py
├── requirements.txt
├── README.md
├── data/
│   └── sample_auth.log
├── src/
│   └── sentinellite/
│       ├── __init__.py
│       ├── detector.py
│       ├── log_parser.py
│       └── reporting.py
└── tests/
    └── test_detector.py
```

## Disclaimer

This project is for educational and defensive security monitoring
purposes. Use authorized and appropriate log data only.

