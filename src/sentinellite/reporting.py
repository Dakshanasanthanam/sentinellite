from datetime import datetime, timezone


def build_report(events, errors, alerts):
    """Build a summary report from parsed events and detected alerts."""
    severity_counts = {}

    for alert in alerts:
        severity = alert["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "invalid_records": len(errors),
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "alerts": alerts,
    }
