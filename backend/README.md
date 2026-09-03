# Guardian Email Intel — P1

P1 is a Python 3.11 FastAPI service that analyzes raw email **headers** and returns a stable `AnalysisResponse` JSON contract. P2 (the web/geolocation layer) and P3 (the Gmail Add-on) should consume this response without changing the field names in `app/models/schemas.py`; communicate any contract change to the team first.

## Setup and run

From the `backend` directory, using Python 3.11:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API listens at `http://127.0.0.1:8000`; interactive documentation is at `/docs`.

## API examples

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Upload an `.eml` file:

```bash
curl -X POST http://127.0.0.1:8000/analyze -F "file=@message.eml"
```

Send raw email text as JSON:

```bash
curl -X POST http://127.0.0.1:8000/analyze -H "Content-Type: application/json" -d '{"raw_email":"From: sender@example.com\nSubject: Test\n\nHello"}'
```

Uploads and JSON inputs over 10 MB receive HTTP 413. Invalid emails receive a descriptive HTTP 400; absent input receives HTTP 422. DNS fallback is limited to three seconds and returns `unknown` plus a warning when unavailable.

## Tests

```bash
pytest
```

The tests include clean, typosquatted, authentication-failure, and no-Authentication-Results sample messages, as well as malformed and empty-request cases.
