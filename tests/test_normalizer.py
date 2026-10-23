from backend.normalizer import NormalizationError, normalize_splunk_payload


def test_normalizes_network_fields_timestamp_and_severity():
    alerts = normalize_splunk_payload(
        {
            "search_name": "VPC RDP Connections",
            "sid": "splunk-sid-1",
            "results": [
                {
                    "_time": "2026-10-24T02:00:00+02:00",
                    "srcaddr": "192.0.2.10",
                    "dest_ip": "2001:db8::1",
                    "srcport": "3389",
                    "dstport": 445,
                    "protocol": "TCP",
                    "action": "allowed",
                    "host": "firewall-01",
                    "severity": "WARNING",
                    "message": "Remote desktop connection",
                }
            ],
        }
    )

    alert = alerts[0]
    assert alert.source == "splunk"
    assert alert.alert_name == "VPC RDP Connections"
    assert alert.timestamp == "2026-10-24T00:00:00Z"
    assert alert.severity == "medium"
    assert alert.category == "network_security"
    assert alert.source_ip == "192.0.2.10"
    assert alert.destination_ip == "2001:db8::1"
    assert alert.source_port == 3389
    assert alert.destination_port == 445
    assert alert.protocol == "TCP"
    assert alert.action == "allowed"
    assert alert.host == "firewall-01"
    assert alert.raw_metadata["splunk_sid"] == "splunk-sid-1"


def test_missing_optional_fields_remain_null_and_unknown_severity_is_not_guessed():
    alert = normalize_splunk_payload(
        {"search_name": "Unknown severity", "results": [{"severity": "urgent"}]}
    )[0]

    assert alert.severity is None
    assert alert.timestamp is None
    assert alert.source_ip is None
    assert alert.destination_ip is None
    assert alert.source_port is None
    assert alert.destination_port is None
    assert alert.protocol is None
    assert alert.action is None
    assert alert.host is None


def test_malformed_ip_port_and_timestamp_are_null_but_context_is_preserved():
    alert = normalize_splunk_payload(
        {
            "sid": "malformed-values",
            "results": [
                {
                    "src_ip": "not-an-ip",
                    "dstaddr": "198.51.100.4",
                    "srcport": "70000",
                    "dstport": "http",
                    "_time": "not-a-timestamp",
                    "custom_field": "kept in metadata",
                }
            ],
        }
    )[0]

    assert alert.source_ip is None
    assert alert.destination_ip == "198.51.100.4"
    assert alert.source_port is None
    assert alert.destination_port is None
    assert alert.timestamp is None
    assert alert.raw_metadata["splunk_event"]["custom_field"] == "kept in metadata"


def test_unix_epoch_zero_is_normalized_in_utc():
    alert = normalize_splunk_payload({"results": [{"_time": 0}]})[0]

    assert alert.timestamp == "1970-01-01T00:00:00Z"


def test_credentials_are_removed_recursively_from_normalized_output():
    alert = normalize_splunk_payload(
        {
            "sid": "safe-id",
            "session_key": "root-session",
            "api_token": "root-token",
            "results": [
                {
                    "password": "event-password",
                    "authorization": "event-auth",
                    "event_id": "event-9",
                    "context": {"client_secret": "nested-secret", "note": "kept"},
                }
            ],
        }
    )[0]
    encoded = str(alert.model_dump(mode="json")).casefold()

    for forbidden in (
        "root-session",
        "root-token",
        "event-password",
        "event-auth",
        "nested-secret",
        "session_key",
        "password",
        "authorization",
        "client_secret",
    ):
        assert forbidden not in encoded
    assert alert.raw_metadata["splunk_event"]["event_id"] == "event-9"
    assert alert.raw_metadata["splunk_event"]["context"]["note"] == "kept"


def test_results_object_and_single_result_alias_are_supported():
    alerts_from_results = normalize_splunk_payload(
        {"sid": "single", "results": {"srcaddr": "192.0.2.20"}}
    )
    alerts_from_result = normalize_splunk_payload(
        {"sid": "singular", "result": {"dst_ip": "198.51.100.20"}}
    )

    assert len(alerts_from_results) == 1
    assert alerts_from_results[0].source_ip == "192.0.2.20"
    assert len(alerts_from_result) == 1
    assert alerts_from_result[0].destination_ip == "198.51.100.20"


def test_multiple_alerts_have_unique_ids():
    alerts = normalize_splunk_payload(
        {"results": [{"host": "one"}, {"host": "two"}]}
    )

    assert len({alert.alert_id for alert in alerts}) == 2


def test_invalid_result_structure_raises_normalization_error():
    try:
        normalize_splunk_payload({"results": [None]})
    except NormalizationError as error:
        assert str(error) == "Each Splunk result must be a JSON object"
    else:
        raise AssertionError("Expected unsupported result structure to be rejected")


def test_severity_mapping_is_consistent():
    values = {
        severity: normalize_splunk_payload({"severity": severity})[0].severity
        for severity in ("critical", "high", "medium", "warning", "low", "info")
    }

    assert values == {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "warning": "medium",
        "low": "low",
        "info": "low",
    }
