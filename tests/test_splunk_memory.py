import json

import pytest

from integrations import splunk_memory


def test_retrieve_for_saved_alert_builds_fingerprint_and_candidates(
    monkeypatch, tmp_path
):
    alert = {
        "alert_id": "SYNTH-ALERT-001",
        "alert_name": "Synthetic phishing event",
        "timestamp": "2026-10-24T00:00:00Z",
        "severity": "high",
    }
    filename = "normalized_alert_synthetic.json"
    (tmp_path / filename).write_text(json.dumps(alert), encoding="utf-8")
    monkeypatch.setattr(splunk_memory, "NORMALIZED_ALERTS_DIR", tmp_path)
    monkeypatch.setattr(
        splunk_memory,
        "search_similar_incidents",
        lambda incident, top_k: [
            {"incident_id": "INC-SYNTHETIC", "vector_score": 0.9}
        ],
    )

    result = splunk_memory.retrieve_for_saved_alert(filename)

    assert result["alert_id"] == alert["alert_id"]
    assert result["fingerprint"]["events"][0]["event_type"] == (
        "synthetic phishing event; severity: high"
    )
    assert result["candidates"] == [
        {"incident_id": "INC-SYNTHETIC", "vector_score": 0.9}
    ]


@pytest.mark.parametrize(
    "filename",
    (
        "../normalized_alert_synthetic.json",
        r"..\normalized_alert_synthetic.json",
        "normalized_alert_synthetic.txt",
        None,
    ),
)
def test_retrieve_for_saved_alert_rejects_invalid_filenames(filename):
    with pytest.raises(ValueError, match="JSON filename"):
        splunk_memory.retrieve_for_saved_alert(filename)


@pytest.mark.parametrize(
    ("contents", "error", "message"),
    (
        ("[]", ValueError, "JSON object"),
        ('{"alert_name": "missing id"}', ValueError, "alert_id"),
        ('{"alert_id": "SYNTH-EMPTY"}', ValueError, "searchable fields"),
    ),
)
def test_retrieve_for_saved_alert_rejects_invalid_or_empty_data(
    monkeypatch, tmp_path, contents, error, message
):
    filename = "normalized_alert_synthetic.json"
    (tmp_path / filename).write_text(contents, encoding="utf-8")
    monkeypatch.setattr(splunk_memory, "NORMALIZED_ALERTS_DIR", tmp_path)

    with pytest.raises(error, match=message):
        splunk_memory.retrieve_for_saved_alert(filename)


def test_retrieve_for_saved_alert_reports_missing_and_invalid_json(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(splunk_memory, "NORMALIZED_ALERTS_DIR", tmp_path)

    with pytest.raises(FileNotFoundError):
        splunk_memory.retrieve_for_saved_alert("missing.json")

    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{invalid", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        splunk_memory.retrieve_for_saved_alert(invalid_json.name)
