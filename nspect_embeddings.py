
from memory.historical_store import load_incidents
from matching.fingerprint import build_fingerprint
from memory.embedding import fingerprint_to_text

new_incident = {
    "incident_id": "NEW-001",
    "events": [
        {
            "seq": 1,
            "event_type": "phishing_email_click",
            "technique": "T1566",
            "timestamp": "2026-10-23T10:00:00Z",
        },
        {
            "seq": 2,
            "event_type": "powershell_encoded_command",
            "technique": "T1059.001",
            "timestamp": "2026-10-23T10:03:00Z",
        },
    ],
}

incidents = load_incidents()
selected_ids = {"INC-001", "INC-002"}

for incident in incidents:
    if incident["incident_id"] in selected_ids:
        fingerprint = build_fingerprint(incident)
        print(f"\n--- {incident['incident_id']} ---")
        print(fingerprint_to_text(fingerprint))

print("\n--- NEW-001 ---")
print(fingerprint_to_text(build_fingerprint(new_incident)))
