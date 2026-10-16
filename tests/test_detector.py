from src.sentinellite.log_parser import parse_log_file
from src.sentinellite.detector import detect_repeated_failures


def test_detects_repeated_failed_logins():
    events, errors = parse_log_file("data/sample_auth.log")

    alerts = detect_repeated_failures(events)

    assert errors == []
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.0.2.11"
    assert alerts[0]["event_count"] == 5
    assert alerts[0]["severity"] == "HIGH"


def test_no_alert_when_threshold_is_not_reached():
    events, errors = parse_log_file("data/sample_auth.log")

    alerts = detect_repeated_failures(events, threshold=6)

    assert alerts == []
