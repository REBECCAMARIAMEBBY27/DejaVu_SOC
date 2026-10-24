
from difflib import SequenceMatcher


def sequence_similarity(current_events, historical_events):
    """Compare the order of events in two incidents."""

    if not current_events or not historical_events:
        return 0.0

    return SequenceMatcher(
        None,
        current_events,
        historical_events
    ).ratio()


def attack_similarity(current_techniques, historical_techniques):
    """Compare the MITRE ATT&CK techniques used."""

    current = set(current_techniques or [])
    historical = set(historical_techniques or [])

    if not current or not historical:
        return 0.0

    common = current.intersection(historical)
    all_techniques = current.union(historical)

    return len(common) / len(all_techniques)


def score_candidate(current, candidate):
    """Calculate how similar one old incident is to the new incident."""

    event_score = sequence_similarity(
        current.get("event_sequence", []),
        candidate.get("event_sequence", [])
    )

    technique_score = attack_similarity(
        current.get("mitre_techniques", []),
        candidate.get("mitre_techniques", [])
    )

    # Initial teaching version: give both signals equal importance.
    final_score = (event_score + technique_score) / 2

    return {
        "incident_id": candidate["incident_id"],
        "event_score": round(event_score, 3),
        "technique_score": round(technique_score, 3),
        "final_score": round(final_score, 3)
    }


def rank_candidates(current, candidates):
    """Rank old incidents from most similar to least similar."""

    results = [
        score_candidate(current, candidate)
        for candidate in candidates
    ]

    return sorted(
        results,
        key=lambda result: result["final_score"],
        reverse=True
    )

def find_matches(current, candidates, threshold=0.70):
    """Return good matches, or report that none were found."""

    ranked = rank_candidates(current, candidates)

    good_matches = [
        incident for incident in ranked
        if incident["final_score"] >= threshold
    ]

    if not good_matches:
        return {
            "status": "NO_GOOD_MATCH",
            "matches": []
        }

    return {
        "status": "MATCH_FOUND",
        "matches": good_matches
    }


if __name__ == "__main__":
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
            "mitre_techniques": ["T1110", "T1059.001"]
        },
        {
            "incident_id": "HIST-002",
            "event_sequence": [
                "failed_login",
                "failed_login"
            ],
            "mitre_techniques": ["T1110"]
        },
        {
            "incident_id": "HIST-003",
            "event_sequence": [
                "dns_lookup",
                "web_request"
            ],
            "mitre_techniques": ["T1071.001"]
        }
    ]

    
    result = find_matches(
        current_incident,
        historical_incidents
    )

    print("\nMatch status:", result["status"])

    if result["status"] == "MATCH_FOUND":
        print("\nSimilar historical incidents:")

        for incident in result["matches"]:
            print(incident)
    else:
        print("No sufficiently similar historical incident found.")

