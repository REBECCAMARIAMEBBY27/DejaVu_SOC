from fastapi import FastAPI, Request

from backend.config import NORMALIZED_ALERTS_DIRECTORY
from backend.webhook_receiver import receive_splunk_webhook

app = FastAPI()
app.state.normalized_alerts_directory = NORMALIZED_ALERTS_DIRECTORY


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/splunk/webhook")
async def splunk_webhook(request: Request) -> dict[str, object]:
    return await receive_splunk_webhook(request)
