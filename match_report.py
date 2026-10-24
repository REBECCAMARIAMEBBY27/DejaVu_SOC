
def create_match_report(current_incident, match_results, historical_incidents):
    """Create a readable report explaining historical incident matches."""

    report = []
    status = match_results["status"]

    report.append("=" * 50)
    report.append("DEJA VU SOC - INCIDENT MATCH REPORT")
    report.append("=" * 50)

    report.append(f"Current incident: {current_incident.get('incident_id', 'Unknown')}")
    report.append(f"Match status: {status}")
    report.append("")

    if status != "MATCH_FOUND":
        report.append("No sufficiently similar historical incident was found.")
        report.append("Do not assume that an unrelated past incident applies.")
        report.append("Investigate using the evidence available for the current alert.")
        return "\n".join(report)

    for match in match_results["matches"]:
        incident_id = match["incident_id"]

        # Find the full historical incident using its ID.
        historical = next(
            (
                incident for incident in historical_incidents
                if incident.get("incident_id") == incident_id
            ),
            None
        )

        report.append(f"Matching historical incident: {incident_id}")
        report.append(f"Overall similarity score: {match['final_score']:.2f}")
        report.append(f"Event sequence similarity: {match['event_score']:.2f}")
        report.append(f"ATT&CK technique similarity: {match['technique_score']:.2f}")
        report.append("")

        if historical is None:
            report.append("Full historical incident details were not found.")
            report.append("")
            continue

        current_events = set(current_incident.get("event_sequence", []))
        old_events = set(historical.get("event_sequence", []))

        shared_events = current_events & old_events
        different_current_events = current_events - old_events
        previous_only_events = old_events - current_events

        report.append("Events present in both incidents:")
        report.extend(
            f"  - {event}" for event in sorted(shared_events)
        ) if shared_events else report.append("  - None identified")

        report.append("")

        report.append("Events only in the current incident:")
        report.extend(
            f"  - {event}" for event in sorted(different_current_events)
        ) if different_current_events else report.append("  - None identified")

        report.append("")

        report.append("Events only in the historical incident:")
        report.extend(
            f"  - {event}" for event in sorted(previous_only_events)
        ) if previous_only_events else report.append("  - None identified")

        current_techniques = set(current_incident.get("mitre_techniques", []))
        old_techniques = set(historical.get("mitre_techniques", []))

        report.append("")
        report.append("MITRE ATT&CK techniques shared:")
        shared_techniques = current_techniques & old_techniques

        report.extend(
            f"  - {technique}" for technique in sorted(shared_techniques)
        ) if shared_techniques else report.append("  - None identified")

        report.append("")
        report.append("Previously recorded response actions:")

        actions = historical.get("response_actions", [])

        if actions:
            report.extend(f"  - {action}" for action in actions)
        else:
            report.append("  - No historical response actions recorded.")

        report.append("")
        report.append("Previously recorded outcome:")
        report.append(historical.get("outcome") or "No historical outcome recorded.")
        report.append("")
        report.append("-" * 50)

    return "\n".join(report)

if __name__ == "__main__":
    from scoring import find_matches

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
            "event_sequence": [
                "failed_login",
                "successful_login",
                "suspicious_powershell"
            ],
            "mitre_techniques": ["T1110", "T1059.001"],
            "response_actions": [
                "Investigate the account",
                "Review suspicious process activity"
            ],
            "outcome": "Contained"
        }
    ]

    results = find_matches(current_incident, historical_incidents)

    report_text = create_match_report(
        current_incident,
        results,
        historical_incidents
    )

    print(report_text)
