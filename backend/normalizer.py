import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class NormalizationError(ValueError):
    pass


class NormalizedAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: Literal["splunk"] = "splunk"
    alert_name: str | None = None
    timestamp: str | None = None
    severity: str | None = None
    category: str | None = None
    description: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    action: str | None = None
    host: str | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "authorization",
    "cookie",
    "session_key",
    "passphrase",
    "apikey",
    "api_key",
    "private_key",
    "access_key",
)


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).casefold().replace("-", "_")
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _sanitize(item)
            for key, item in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def _first_value(event: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = event.get(key)
        if value is not None and value != "":
            return value
    return None


def _event_or_parent_value(
    event: dict[str, Any],
    payload: dict[str, Any],
    *keys: str,
) -> Any:
    value = _first_value(event, *keys)
    return _first_value(payload, *keys) if value is None else value


def _as_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _normalize_timestamp(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            parsed = datetime.fromtimestamp(value, tz=timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                parsed = datetime.fromtimestamp(float(text), tz=timezone.utc)
            except ValueError:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                parsed = parsed.astimezone(timezone.utc)
        else:
            return None
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_severity(value: Any) -> str | None:
    text = _as_text(value)
    if text is None:
        return None
    severity = text.casefold().strip()
    mappings = {
        "critical": "critical",
        "emergency": "critical",
        "fatal": "critical",
        "high": "high",
        "error": "high",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "low": "low",
        "info": "low",
        "informational": "low",
        "notice": "low",
    }
    return mappings.get(severity)


def _normalize_ip(value: Any) -> str | None:
    text = _as_text(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _normalize_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, str) and not re.fullmatch(r"\d+", value.strip()):
            return None
        port = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return port if 0 <= port <= 65535 else None


def _event_metadata(
    payload: dict[str, Any],
    event: dict[str, Any],
    has_result: bool,
) -> dict[str, Any]:
    parent = {
        key: value
        for key, value in payload.items()
        if key not in {"results", "result"}
    }
    metadata: dict[str, Any] = {"splunk_alert_metadata": _sanitize(parent)}

    sid = _first_value(payload, "sid", "search_id")
    search_name = _first_value(payload, "search_name", "alert_name", "name")
    if sid is not None:
        metadata["splunk_sid"] = _sanitize(sid)
    if search_name is not None:
        metadata["splunk_search_name"] = _sanitize(search_name)
    if has_result:
        metadata["splunk_event"] = _sanitize(event)
    return metadata


def _normalize_event(
    payload: dict[str, Any],
    event: dict[str, Any],
    has_result: bool,
) -> NormalizedAlert:
    alert_name = _as_text(
        _first_value(payload, "search_name", "alert_name", "name")
        or _first_value(event, "search_name", "alert_name", "name")
    )
    timestamp = _normalize_timestamp(
        _event_or_parent_value(
            event,
            payload,
            "_time",
            "timestamp",
            "time",
            "event_time",
            "trigger_time",
            "alert_time",
        )
    )
    severity = _normalize_severity(
        _event_or_parent_value(event, payload, "severity", "urgency", "priority")
    )

    source_ip = _normalize_ip(_first_value(event, "srcaddr", "src_ip", "source_ip"))
    destination_ip = _normalize_ip(
        _first_value(event, "dstaddr", "destaddr", "dest_ip", "dst_ip", "destination_ip")
    )

    network_fields_present = any(
        key in event
        for key in (
            "srcaddr",
            "src_ip",
            "source_ip",
            "dstaddr",
            "destaddr",
            "dest_ip",
            "dst_ip",
            "destination_ip",
            "srcport",
            "src_port",
            "source_port",
            "dstport",
            "destport",
            "dest_port",
            "dst_port",
            "destination_port",
            "protocol",
            "proto",
        )
    )
    category = _as_text(_first_value(event, "category"))
    if category is None:
        category = _as_text(_first_value(payload, "category"))
    if category is None and network_fields_present:
        category = "network_security"

    description = _as_text(
        _first_value(event, "description", "message", "_raw", "signature")
    )
    if description is None:
        description = _as_text(
            _first_value(payload, "description", "message", "_raw", "signature")
        )

    return NormalizedAlert(
        alert_name=alert_name,
        timestamp=timestamp,
        severity=severity,
        category=category,
        description=description,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=_normalize_port(_first_value(event, "srcport", "src_port")),
        destination_port=_normalize_port(_first_value(event, "dstport", "destport", "dest_port", "dst_port")),
        protocol=_as_text(_first_value(event, "protocol", "proto")),
        action=_as_text(_first_value(event, "action", "action_type")),
        host=_as_text(_first_value(event, "host", "hostname", "dvc")),
        raw_metadata=_event_metadata(payload, event, has_result),
    )


def normalize_splunk_payload(payload: dict[str, Any]) -> list[NormalizedAlert]:
    if not isinstance(payload, dict):
        raise NormalizationError("Splunk payload must be a JSON object")

    raw_results = payload.get("results", payload.get("result"))
    if raw_results is None:
        events = [(payload, False)]
    elif isinstance(raw_results, dict):
        events = [(raw_results, True)]
    elif isinstance(raw_results, list):
        if not raw_results:
            raise NormalizationError("Splunk results must contain at least one event")
        if any(not isinstance(event, dict) for event in raw_results):
            raise NormalizationError("Each Splunk result must be a JSON object")
        events = [(event, True) for event in raw_results]
    else:
        raise NormalizationError("Splunk results must be an object or array of objects")

    sanitized_payload = _sanitize(payload)
    if not sanitized_payload:
        raise NormalizationError("Splunk payload contains no usable alert data")

    return [
        _normalize_event(payload, event, has_result)
        for event, has_result in events
    ]
