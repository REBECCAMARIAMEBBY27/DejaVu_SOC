import hmac
import json
import logging
import os
import tempfile
import uuid
from pathlib import Path

from fastapi import HTTPException, Request

from backend.config import get_webhook_secret
from backend.normalizer import NormalizationError, normalize_splunk_payload

logger = logging.getLogger(__name__)


class AlertStorageError(Exception):
    pass


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"Non-standard JSON constant: {value}")


def authenticate_webhook(request: Request) -> None:
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("Rejected Splunk webhook authentication")
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expected_secret = get_webhook_secret()
    if expected_secret is None:
        logger.error("Splunk webhook authentication is not configured")
        raise HTTPException(
            status_code=503,
            detail="Webhook authentication is not configured",
        )

    if not hmac.compare_digest(
        parts[1].encode("utf-8"),
        expected_secret.encode("utf-8"),
    ):
        logger.warning("Rejected Splunk webhook authentication")
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def store_normalized_alert(alert: dict[str, object], alerts_directory: Path) -> str:
    temporary_path: str | None = None
    try:
        alerts_directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=alerts_directory,
            prefix=".alert_",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(
                alert,
                temporary_file,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        while True:
            filename = f"normalized_alert_{uuid.uuid4().hex}.json"
            destination = alerts_directory / filename
            try:
                os.link(temporary_path, destination)
                return filename
            except FileExistsError:
                continue
    except OSError as exc:
        raise AlertStorageError("Could not store the received alert") from exc
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception("Could not clean up temporary alert file")


async def receive_splunk_webhook(request: Request) -> dict[str, object]:
    authenticate_webhook(request)

    try:
        payload = json.loads(
            await request.body(),
            parse_constant=_reject_nonstandard_json_constant,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON") from None

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON payload must be an object")

    try:
        normalized_alerts = normalize_splunk_payload(payload)
    except NormalizationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    try:
        filenames = [
            store_normalized_alert(
                alert.model_dump(mode="json"),
                request.app.state.normalized_alerts_directory,
            )
            for alert in normalized_alerts
        ]
    except AlertStorageError:
        logger.exception("Failed to store normalized Splunk alert")
        raise HTTPException(status_code=500, detail="Alert could not be stored") from None

    logger.info("Stored %d normalized Splunk alert(s)", len(filenames))
    return {
        "status": "received",
        "normalized": True,
        "stored_count": len(filenames),
        "filenames": filenames,
    }
