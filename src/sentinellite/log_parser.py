from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


EXPECTED_COLUMNS = ["timestamp", "source_ip", "username", "event_type"]


def parse_log_file(file_path):
    """Read a CSV-style authentication log and validate its records."""
    records = []
    errors = []

    with Path(file_path).open("r", encoding="utf-8") as log_file:
        for line_number, raw_line in enumerate(log_file, start=1):
            line = raw_line.strip()

            if not line:
                continue

            parts = [part.strip() for part in line.split(",")]

            if len(parts) != 4:
                errors.append(
                    {"line": line_number, "error": "Expected four fields"}
                )
                continue

            timestamp_text, source_ip, username, event_type = parts

            try:
                timestamp = datetime.fromisoformat(
                    timestamp_text.replace("Z", "+00:00")
                )

                if timestamp.tzinfo is None:
                    raise ValueError("Timestamp must include a timezone")

                timestamp = timestamp.astimezone(timezone.utc)

            except ValueError:
                errors.append(
                    {"line": line_number, "error": "Invalid timestamp"}
                )
                continue

            if not source_ip or not username:
                errors.append(
                    {"line": line_number, "error": "Missing IP or username"}
                )
                continue

            if event_type not in {"LOGIN_SUCCESS", "LOGIN_FAILED"}:
                errors.append(
                    {"line": line_number, "error": "Unknown event type"}
                )
                continue

            records.append(
                {
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "username": username,
                    "event_type": event_type,
                }
            )

    events = pd.DataFrame(records, columns=EXPECTED_COLUMNS)
    return events, errors
