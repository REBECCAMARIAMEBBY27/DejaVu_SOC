
import sys
import unittest
from pathlib import Path

# Allow Python to find the main project folder and generator.py.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "playbooks"))

from generator import generate_playbook


class TestGenerator(unittest.TestCase):

    def test_generates_login_investigation_recommendations(self):
        current_incident = {
            "incident_id": "NEW-001",
            "event_sequence": ["failed_login", "successful_login"],
            "mitre_techniques": ["T1110"]
        }

        result = generate_playbook(
            current_incident,
            {"status": "NO_GOOD_MATCH", "matches": []},
            []
        )

        self.assertTrue(result["recommendations"])
        self.assertTrue(
            any("login" in item.lower()
                for item in result["recommendations"])
        )
        self.assertTrue(result["requires_analyst_review"])

    def test_no_match_does_not_add_historical_actions(self):
        current_incident = {
            "incident_id": "NEW-002",
            "event_sequence": ["suspicious_powershell"],
            "mitre_techniques": ["T1059.001"]
        }

        historical_incidents = [
            {
                "incident_id": "HIST-001",
                "response_actions": ["Isolate the computer"]
            }
        ]

        result = generate_playbook(
            current_incident,
            {"status": "NO_GOOD_MATCH", "matches": []},
            historical_incidents
        )

        self.assertFalse(
            any("historical reference" in item.lower()
                for item in result["recommendations"])
        )

    def test_unknown_events_get_general_guidance(self):
        current_incident = {
            "incident_id": "NEW-003",
            "event_sequence": [],
            "mitre_techniques": []
        }

        result = generate_playbook(
            current_incident,
            {"status": "NO_GOOD_MATCH", "matches": []},
            []
        )

        self.assertTrue(result["recommendations"])
        self.assertTrue(result["requires_analyst_review"])


if __name__ == "__main__":
    unittest.main()
