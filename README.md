# Déjà Vu SOC Splunk webhook

The backend accepts JSON from the existing DS-Compass Splunk custom alert
action at `POST /splunk/webhook`. The request is authenticated with a Bearer
token, normalized into one alert per result event, and saved as separate JSON
files under the project-root `data/normalized_alerts/` directory. Incoming raw
payloads are not saved as separate files. Existing files under `data/alerts/`
are historical data and are left untouched.

## Install and configure

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Set `SPLUNK_WEBHOOK_SECRET` to the same value used by the existing sender. The
receiver loads it from a project-root `.env` file or the process environment;
the process environment takes precedence. Do not commit `.env`.

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
```

Replace the placeholder in `.env` with the shared secret. Do not expose the
secret in logs or requests you share.

## Start and check the backend

Start from the project root:

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```

In a second terminal:

```powershell
curl.exe http://127.0.0.1:8001/health
```

The expected response is `{"status":"ok"}`.

## Normalized alert schema

Every event produces an object with this shape. Optional fields are `null`
when the payload has no valid corresponding value.

```json
{
  "alert_id": "generated-uuid",
  "source": "splunk",
  "alert_name": null,
  "timestamp": null,
  "severity": null,
  "category": null,
  "description": null,
  "source_ip": null,
  "destination_ip": null,
  "source_port": null,
  "destination_port": null,
  "protocol": null,
  "action": null,
  "host": null,
  "raw_metadata": {
    "splunk_alert_metadata": {},
    "splunk_sid": "when-present",
    "splunk_search_name": "when-present",
    "splunk_event": {}
  }
}
```

`raw_metadata` preserves sanitized parent alert context and each result's
additional fields. Credential-like keys such as `session_key`, passwords,
secrets, tokens, and authorization values are excluded recursively.

### Field mapping and rules

- Alert name: `search_name`, `alert_name`, or `name`.
- Event time: `_time`, `timestamp`, `time`, `event_time`, `trigger_time`, or
  `alert_time`; ISO timestamps and Unix epoch values are converted to UTC ISO
  8601 ending in `Z`. Missing or unparseable timestamps become `null`.
- Severity: recognized labels map consistently: `critical`/`emergency`/
  `fatal` → `critical`; `high`/`error` → `high`; `medium`/`moderate`/
  `warning` → `medium`; `low`/`info`/`informational`/`notice` → `low`.
  Unknown or missing levels remain `null`; no level is inferred from event
  text.
- Network fields: `srcaddr`/`src_ip`/`source_ip` → `source_ip`;
  `dstaddr`/`dest_ip`/`dst_ip`/`destination_ip` → `destination_ip`;
  `srcport`/`src_port` → `source_port`;
  `dstport`/`dest_port`/`dst_port` → `destination_port`.
  IPs are validated and ports must be integers from 0 to 65535; invalid
  optional values become `null` while the supplied event context remains in
  sanitized metadata.
- `protocol`/`proto`, `action`/`action_type`, and `host`/`hostname`/`dvc` map
  to their corresponding normalized fields.
- `network_security` is assigned when network fields are present and no
  explicit category is supplied. Otherwise category is copied when present,
  or remains `null`.
- `description`, `message`, `_raw`, or `signature` are used as the description
  when present. No event description is invented.
- A payload without `results` is normalized as one alert-level event.
  `results` or `result` may be one object or an array of objects. Each result
  in an array creates a distinct alert with the parent `sid` and search name
  retained in metadata. Unsupported result shapes return HTTP 400.

## Storage and response

Files are written under `data/normalized_alerts/`, resolved relative to the
project files rather than the process working directory. Each normalized
alert is written to its own uniquely named JSON file using a temporary file
and exclusive creation to avoid incomplete writes or overwrites.

A successful request returns, for example:

```json
{
  "status": "received",
  "normalized": true,
  "stored_count": 2,
  "filenames": [
    "normalized_alert_<unique-id>.json",
    "normalized_alert_<unique-id>.json"
  ],
  "retrieval": [
    {
      "filename": "normalized_alert_<unique-id>.json",
      "status": "completed",
      "alert_id": "<alert-id>",
      "fingerprint": {},
      "candidates": [
        {
          "incident_id": "INC-001",
          "vector_score": 0.82
        }
      ]
    }
  ]
}
```

Historical retrieval runs after alerts are saved. If retrieval is unavailable,
the webhook still reports the alert as received and returns a `retrieval`
entry with `status: "failed"`; inspect the backend log for the failure. Scores
rank candidate incidents and are not proof that an alert is malicious.

## Run tests

```powershell
python -m pytest
```

Tests use temporary alert storage and do not modify historical files under
`data/alerts/`.

## Verify a real Splunk delivery

The existing action should send to `http://127.0.0.1:8001/splunk/webhook` when
Splunk and this backend can reach each other at that address. Configure the
same Bearer secret for the action and backend, enable the existing action on a
saved Splunk alert, and trigger that alert through its normal search/condition.
Then check the receiver terminal for its normalized storage log and inspect
the newly created file(s) in `data/normalized_alerts/`.

To list the stored files from PowerShell:

```powershell
Get-ChildItem .\data\normalized_alerts\*.json
```

To inspect an individual file, use its filename from the listing:

```powershell
Get-Content .\data\normalized_alerts\<filename>.json
```

Local tests or a manually constructed HTTP request only verify the receiver;
they do not prove a real Splunk alert was delivered. Real Splunk delivery must
be verified independently.

## Frontend dashboard

The React + Vite + TypeScript + Tailwind dashboard is in `frontend/`.
Only the existing `GET /health` route is called by the browser. Alert rows,
dashboard metrics, incident details, and comparison scores are explicitly
labelled demo data because this backend does not expose read APIs for saved
alerts or historical incidents, or an analyst-facing retrieval endpoint. The
authenticated Splunk webhook is not called from the browser, so its bearer
secret is never included in frontend code.

Install Node.js 20 or later, then start the backend in one PowerShell terminal:

```powershell
cd C:\Users\ebbyt\soc\DejaVu_SOC
$env:SPLUNK_WEBHOOK_SECRET = "your-local-development-token"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```

In another terminal, install frontend dependencies and start Vite:

```powershell
cd C:\Users\ebbyt\soc\DejaVu_SOC\frontend
npm install
Copy-Item .env.example .env
npm run dev
```

Open the local URL printed by Vite. The development server proxies `/api`
requests to `http://127.0.0.1:8001` by default. To use a different local
backend, set `VITE_PROXY_TARGET` in `frontend/.env`. `VITE_API_BASE_URL`
defaults to `/api`; direct cross-origin production access will also require
the backend or a deployment proxy to permit the frontend origin.

Build the frontend with:

```powershell
npm run build
```
