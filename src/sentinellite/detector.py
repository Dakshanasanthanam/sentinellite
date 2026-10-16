from datetime import timedelta


def detect_repeated_failures(events, threshold=5, window_minutes=5):
    """Detect repeated failed logins from one IP within a time window."""
    alerts = []

    failures = events[events["event_type"] == "LOGIN_FAILED"]

    for source_ip, group in failures.groupby("source_ip"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()

        start = 0

        for end in range(len(timestamps)):
            while (
                timestamps[end] - timestamps[start]
                > timedelta(minutes=window_minutes)
            ):
                start += 1

            count = end - start + 1

            if count >= threshold:
                alerts.append({
                    "rule_id": "AUTH-001",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "event_count": count,
                    "first_seen": timestamps[start],
                    "last_seen": timestamps[end],
                    "description": (
                        f"{count} failed login attempts from {source_ip} "
                        f"within {window_minutes} minutes"
                    ),
                })

                break

    return alerts
