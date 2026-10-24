
import json
from pathlib import Path
from typing import Any

from matching.fingerprint import build_fingerprint
from memory.faiss_index import search_similar_incidents


ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_ALERTS_DIR = ROOT / "data" / "normalized_alerts"

PROTOCOL_NAMES = {
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP",
    "58": "ICMPv6",
}


def normalized_alert_to_incident(
    alert: dict[str, Any],
) -> dict[str, Any]:
    """Convert a normalized Splunk alert into a one-event query."""

    alert_id = alert.get("alert_id")
    if not alert_id:
        raise ValueError("Normalized alert is missing alert_id")

    event_type = (
        alert.get("alert_name")
        or alert.get("category")
        or alert.get("description")
        or "unknown"
    )

    details = []

    if alert.get("category"):
        details.append(f"category: {alert['category']}")

    if alert.get("description"):
        details.append(f"description: {alert['description']}")

    if alert.get("severity"):
        details.append(f"severity: {alert['severity']}")

    if alert.get("source_ip"):
        details.append(f"source IP: {alert['source_ip']}")

    if alert.get("destination_ip"):
        details.append(f"destination IP: {alert['destination_ip']}")

    if alert.get("destination_port") is not None:
        details.append(f"destination port: {alert['destination_port']}")

    if alert.get("source_port") is not None:
        details.append(f"source port: {alert['source_port']}")

    if alert.get("protocol"):
        protocol = str(alert["protocol"])
        protocol = PROTOCOL_NAMES.get(protocol, protocol)
        details.append(f"protocol: {protocol}")

    if alert.get("action"):
        details.append(f"action: {alert['action']}")

    if alert.get("host"):
        details.append(f"host: {alert['host']}")

    # This is descriptive text, not a verified attack classification.
    event_label = str(event_type)
    if details:
        event_label += "; " + "; ".join(details)

    return {
        "incident_id": alert_id,
        "events": [
            {
                "seq": 1,
                "event_type": event_label,
                "technique": None,
                "host": alert.get("host"),
                "user": None,
                "timestamp": alert.get("timestamp"),
            }
        ],
    }


def retrieve_for_saved_alert(
    filename: str,
    top_k: int = 3,
) -> dict[str, Any]:
    """Retrieve historical candidates for a saved normalized alert."""

    if Path(filename).name != filename or not filename.endswith(".json"):
        raise ValueError(
            "Provide a JSON filename from normalized_alerts"
        )

    alert_path = NORMALIZED_ALERTS_DIR / filename
    alert = json.loads(alert_path.read_text(encoding="utf-8"))

    incident = normalized_alert_to_incident(alert)
    fingerprint = build_fingerprint(incident)
    candidates = search_similar_incidents(incident, top_k=top_k)

    return {
        "alert_id": alert["alert_id"],
        "fingerprint": fingerprint,
        "candidates": candidates,
    }
