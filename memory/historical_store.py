
import json
from pathlib import Path
from typing import Any

DATA_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "historical_incidents.json"
)


def load_incidents() -> list[dict[str, Any]]:
    with open(DATA_FILE, encoding="utf-8") as file:
        incidents = json.load(file)

    if not isinstance(incidents, list):
        raise ValueError("Historical data must be a JSON list")

    ids = [item.get("incident_id") for item in incidents]

    if any(not incident_id for incident_id in ids):
        raise ValueError("Every incident needs an incident_id")

    if len(ids) != len(set(ids)):
        raise ValueError("Historical incident IDs must be unique")

    return incidents


def get_incident_by_id(incident_id: str):
    for incident in load_incidents():
        if incident["incident_id"] == incident_id:
            return incident

    return None
