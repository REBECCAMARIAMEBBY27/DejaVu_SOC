import json

import pytest
from fastapi.testclient import TestClient

from backend import config
from backend.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_webhook(monkeypatch, tmp_path):
    monkeypatch.delenv("SPLUNK_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("SPLUNK_WEBHOOK_SECRET", "test-secret")
    normalized_directory = tmp_path / "normalized_alerts"
    monkeypatch.setattr(
        app.state,
        "normalized_alerts_directory",
        normalized_directory,
        raising=False,
    )
def post_alert(payload, token="test-secret"):
    return client.post(
        "/splunk/webhook",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


def test_webhook_saves_only_normalized_alerts(tmp_path):
    normalized_directory = tmp_path / "normalized_alerts"
    legacy_raw_directory = tmp_path / "alerts"
    payload = {
        "search_name": "VPC Allowed FTP Connections",
        "sid": "scheduler__admin__search",
        "results": [
            {
                "_time": "2026-10-24T00:00:00Z",
                "srcaddr": "192.0.2.10",
                "dstaddr": "198.51.100.20",
                "srcport": "49152",
                "dstport": 21,
                "protocol": "tcp",
                "action": "allowed",
                "host": "firewall-01",
                "severity": "high",
                "message": "FTP connection allowed",
                "session_key": "must-not-be-saved",
            }
        ],
        "password": "also-not-saved",
    }

    response = post_alert(payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "received"
    assert body["normalized"] is True
    assert body["stored_count"] == 1
    assert len(body["filenames"]) == 1
    saved = json.loads(
        (normalized_directory / body["filenames"][0]).read_text(encoding="utf-8")
    )
    assert saved["source"] == "splunk"
    assert saved["alert_name"] == "VPC Allowed FTP Connections"
    assert "results" not in saved
    assert saved["source_ip"] == "192.0.2.10"
    assert saved["destination_ip"] == "198.51.100.20"
    assert saved["source_port"] == 49152
    assert saved["destination_port"] == 21
    assert saved["severity"] == "high"
    assert saved["host"] == "firewall-01"
    assert "password" not in json.dumps(saved).casefold()
    assert "session_key" not in json.dumps(saved).casefold()
    assert not legacy_raw_directory.exists()


def test_multiple_result_events_create_distinct_normalized_files(tmp_path):
    normalized_directory = tmp_path / "normalized_alerts"
    response = post_alert(
        {
            "search_name": "Network alert",
            "sid": "parent-search-123",
            "results": [
                {"src_ip": "192.0.2.1", "host": "edge-a"},
                {"src_ip": "192.0.2.2", "host": "edge-b"},
            ],
        }
    )

    assert response.status_code == 200
    body = response.json()
    assert body["stored_count"] == 2
    assert len(body["filenames"]) == 2
    assert len(set(body["filenames"])) == 2
    saved = [
        json.loads((normalized_directory / filename).read_text(encoding="utf-8"))
        for filename in body["filenames"]
    ]
    assert [alert["source_ip"] for alert in saved] == ["192.0.2.1", "192.0.2.2"]
    assert all(
        alert["raw_metadata"]["splunk_sid"] == "parent-search-123"
        for alert in saved
    )


def test_payload_without_results_is_normalized(tmp_path):
    normalized_directory = tmp_path / "normalized_alerts"
    response = post_alert(
        {
            "search_name": "Alert-level only",
            "sid": "search-without-results",
            "message": "Search alert fired",
        }
    )

    assert response.status_code == 200
    body = response.json()
    assert body["stored_count"] == 1
    alert = json.loads(
        (normalized_directory / body["filenames"][0]).read_text(encoding="utf-8")
    )
    assert alert["alert_name"] == "Alert-level only"
    assert alert["description"] == "Search alert fired"


def test_invalid_json_is_rejected():
    response = client.post(
        "/splunk/webhook",
        content='{"results":',
        headers={
            "Authorization": "Bearer test-secret",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400


def test_invalid_token_is_rejected():
    response = post_alert({"search_name": "test"}, token="wrong-secret")

    assert response.status_code == 401


def test_unsupported_payload_is_rejected():
    response = client.post(
        "/splunk/webhook",
        json={"search_name": "bad result type", "results": "not-an-array"},
        headers={"Authorization": "Bearer test-secret"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Splunk results must be an object or array of objects"
    }


def test_storage_failure_returns_server_error(monkeypatch, tmp_path):
    normalized_directory = app.state.normalized_alerts_directory
    blocked_path = tmp_path / "not-a-directory"
    blocked_path.write_text("block", encoding="utf-8")
    monkeypatch.setattr(
        app.state,
        "normalized_alerts_directory",
        blocked_path,
        raising=False,
    )

    response = post_alert({"search_name": "storage failure"})

    assert response.status_code == 500
    assert response.json() == {"detail": "Alert could not be stored"}
    assert not normalized_directory.exists()


def test_health_is_available_without_authentication():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_missing_secret_is_reported(monkeypatch, tmp_path):
    monkeypatch.delenv("SPLUNK_WEBHOOK_SECRET", raising=False)
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)

    response = post_alert({"search_name": "no configured secret"})

    assert response.status_code == 503
