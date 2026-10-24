
import sys
import unittest
from pathlib import Path

# Let Python find scoring.py in the main project folder.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scoring import sequence_similarity, attack_similarity, rank_candidates


class TestScoring(unittest.TestCase):

    def test_identical_event_sequences(self):
        events = ["failed_login", "successful_login", "suspicious_powershell"]

        score = sequence_similarity(events, events)

        self.assertEqual(score, 1.0)

    def test_different_event_sequences(self):
        current = ["failed_login", "successful_login"]
        historical = ["dns_lookup", "web_request"]

        score = sequence_similarity(current, historical)

        self.assertLess(score, 1.0)

    def test_identical_attack_techniques(self):
        current = ["T1110", "T1059.001"]
        historical = ["T1110", "T1059.001"]

        score = attack_similarity(current, historical)

        self.assertEqual(score, 1.0)

    def test_rank_best_match_first(self):
        current = {
            "event_sequence": ["failed_login", "successful_login"],
            "mitre_techniques": ["T1110"]
        }

        candidates = [
            {
                "incident_id": "HIST-002",
                "event_sequence": ["dns_lookup", "web_request"],
                "mitre_techniques": ["T1071.001"]
            },
            {
                "incident_id": "HIST-001",
                "event_sequence": ["failed_login", "successful_login"],
                "mitre_techniques": ["T1110"]
            }
        ]

        rankings = rank_candidates(current, candidates)

        self.assertEqual(rankings[0]["incident_id"], "HIST-001")


    def test_find_matches_returns_match_found(self):
        current = {
            "event_sequence": ["failed_login", "successful_login"],
            "mitre_techniques": ["T1110"]
        }

        candidates = [
            {
                "incident_id": "HIST-001",
                "event_sequence": ["failed_login", "successful_login"],
                "mitre_techniques": ["T1110"]
            }
        ]

        from scoring import find_matches
        result = find_matches(current, candidates)

        self.assertEqual(result["status"], "MATCH_FOUND")
        self.assertEqual(result["matches"][0]["incident_id"], "HIST-001")

    def test_find_matches_returns_no_good_match(self):
        current = {
            "event_sequence": ["failed_login", "successful_login"],
            "mitre_techniques": ["T1110"]
        }

        candidates = [
            {
                "incident_id": "HIST-009",
                "event_sequence": ["dns_lookup", "web_request"],
                "mitre_techniques": ["T1071.001"]
            }
        ]

        from scoring import find_matches
        result = find_matches(current, candidates)

        self.assertEqual(result["status"], "NO_GOOD_MATCH")
        self.assertEqual(result["matches"], [])

if __name__ == "__main__":
    unittest.main()
