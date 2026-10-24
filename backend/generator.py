
def generate_playbook(current_incident, match_results, historical_incidents):
    """Generate investigation recommendations from available evidence."""

    recommendations = []

    events = current_incident.get("event_sequence", [])
    techniques = current_incident.get("mitre_techniques", [])

    # Recommendation 1: Investigate login activity.
    if "failed_login" in events:
        recommendations.append(
            "Review failed login attempts, including their source IPs "
            "and affected accounts."
        )

    if "successful_login" in events:
        recommendations.append(
            "Verify whether the successful login was legitimate. "
            "Check the account, login time, source IP, and device."
        )

    # Recommendation 2: Investigate suspicious PowerShell activity.
    if "suspicious_powershell" in events or "T1059.001" in techniques:
        recommendations.append(
            "Review the PowerShell command, its parent process, "
            "and related process activity."
        )

    # Recommendation 3: Investigate brute-force activity.
    if "T1110" in techniques:
        recommendations.append(
            "Check for repeated authentication failures and determine "
            "whether other accounts were targeted."
        )

    # Recommendation 4: Use historical information only when a match exists.
    if match_results.get("status") == "MATCH_FOUND":
        matched_ids = {
            match["incident_id"]
            for match in match_results.get("matches", [])
        }

        for incident in historical_incidents:
            if incident.get("incident_id") in matched_ids:
                actions = incident.get("response_actions", [])

                if actions:
                    recommendations.append(
                        "Historical reference: review the following "
                        "previously recorded response actions for relevance: "
                        + "; ".join(actions)
                    )

    # Remove duplicate recommendations while keeping their order.
    recommendations = list(dict.fromkeys(recommendations))

    if not recommendations:
        recommendations.append(
            "No specific recommendation could be generated from the "
            "available fields. Gather more evidence and investigate "
            "using your organization's approved procedures."
        )

    return {
        "incident_id": current_incident.get("incident_id", "Unknown"),
        "match_status": match_results.get("status", "UNKNOWN"),
        "recommendations": recommendations,
        "requires_analyst_review": True
    }


if __name__ == "__main__":
    # Sample data for testing only.
    current_incident = {
        "incident_id": "NEW-001",
        "event_sequence": [
            "failed_login",
            "successful_login",
            "suspicious_powershell"
        ],
        "mitre_techniques": ["T1110", "T1059.001"]
    }

    historical_incidents = [
        {
            "incident_id": "HIST-001",
            "response_actions": [
                "Investigate the account",
                "Review suspicious process activity"
            ]
        }
    ]

    # Simulated matching result for this test.
    match_results = {
    "status": "NO_GOOD_MATCH",
    "matches": []
}

    playbook = generate_playbook(
        current_incident,
        match_results,
        historical_incidents
    )

    print("\nDEJA VU SOC - INVESTIGATION PLAYBOOK")
    print("=" * 40)
    print("Incident:", playbook["incident_id"])
    print("Match status:", playbook["match_status"])
    print("\nRecommended investigation steps:")

    for number, recommendation in enumerate(
        playbook["recommendations"], start=1
    ):
        print(f"{number}. {recommendation}")

    print("\nAnalyst review required:", playbook["requires_analyst_review"])
