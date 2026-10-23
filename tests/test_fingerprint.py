
from matching.fingerprint import build_fingerprint


def test_fingerprint_preserves_event_order():
    incident = {
        "incident_id": "TEST-001",
        "events": [
            {
                "seq": 2,
                "event_type": "PowerShell_Command",
                "technique": "T1059.001",
                "timestamp": "2026-10-20T10:05:00Z",
            },
            {
                "seq": 1,
                "event_type": "Phishing_Email_Click",
                "technique": "T1566",
                "timestamp": "2026-10-20T10:00:00Z",
            },
        ],
    }

    fingerprint = build_fingerprint(incident)

    assert len(fingerprint["events"]) == 2
    assert fingerprint["events"][0]["event_type"] == "phishing_email_click"
    assert fingerprint["events"][1]["event_type"] == "powershell_command"
    assert fingerprint["events"][1]["gap_seconds"] == 300
    assert fingerprint["techniques"] == ["T1059.001", "T1566"]
