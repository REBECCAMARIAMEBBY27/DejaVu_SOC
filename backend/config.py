import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
NORMALIZED_ALERTS_DIRECTORY = PROJECT_ROOT / "data" / "normalized_alerts"


def get_webhook_secret() -> str | None:
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    secret = os.getenv("SPLUNK_WEBHOOK_SECRET")
    return secret if secret else None
