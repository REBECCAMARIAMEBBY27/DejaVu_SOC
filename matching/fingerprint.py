
from datetime import datetime
from typing import Any


def parse_timestamp(value: str | None):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return None


def build_fingerprint(incident: dict[str, Any]) -> dict[str, Any]:
    events = sorted(
        incident.get("events", []),
        key=lambda event: event.get("seq", 0),
    )

    normalized_events = []
    previous_time = None

    for event in events:
        timestamp = parse_timestamp(event.get("timestamp"))

        gap_seconds = None
        if (
            timestamp is not None
            and previous_time is not None
            and timestamp.tzinfo == previous_time.tzinfo
        ):
            gap_seconds = (
                timestamp - previous_time
            ).total_seconds()

        normalized_events.append({
            "seq": event.get("seq"),
            "event_type": (
                str(event.get("event_type", "unknown"))
                .strip()
                .lower()
            ),
            "technique": event.get("technique"),
            "host": event.get("host"),
            "user": event.get("user"),
            "timestamp": event.get("timestamp"),
            "gap_seconds": gap_seconds,
        })

        if timestamp is not None:
            previous_time = timestamp

    techniques = sorted({
        event["technique"]
        for event in normalized_events
        if event["technique"]
    })

    return {
        "incident_id": incident.get("incident_id"),
        "events": normalized_events,
        "techniques": techniques,
    }
