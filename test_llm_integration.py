from playbooks.llm_client import generate_with_llm

current_incident = {
    "incident_id": "TEST-001",
    "event_sequence": [
        "failed_login",
        "successful_login",
        "suspicious_powershell"
    ],
    "mitre_techniques": ["T1110", "T1059.001"]
}

match_results = {
    "status": "MATCH_FOUND",
    "matches": [
        {
            "incident_id": "HIST-001",
            "event_score": 1.0,
            "technique_score": 1.0,
            "final_score": 1.0
        }
    ]
}

historical_incidents = [
    {
        "incident_id": "HIST-001",
        "event_sequence": [
            "failed_login",
            "successful_login",
            "suspicious_powershell"
        ],
        "mitre_techniques": ["T1110", "T1059.001"],
        "response_actions": [
            "Reviewed authentication logs",
            "Investigated PowerShell command history"
        ],
        "outcome": "Suspicious activity confirmed"
    }
]

try:
    print("Testing Déjà Vu SOC LLM integration...\n")

    result = generate_with_llm(
        current_incident,
        match_results,
        historical_incidents
    )

    print("SUCCESS! Groq generated an investigation response.\n")
    print("=" * 60)
    print(result)
    print("=" * 60)

except Exception as error:
    print("Integration test failed.")
    print("Error type:", type(error).__name__)
    print("Details:", str(error))