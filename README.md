# IntentShield v2 — Full-stack prototype

## Features
- FastAPI backend + SQLite
- Ed25519-signed intent tokens
- AI-agent registration and delegated scope
- Transaction-vs-intent verification
- Fraud-journey event graph
- Browser WebAuthn/passkey ceremony demo
- Swagger/OpenAPI at `/docs`

## Run
Python 3.11+:
```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000 and http://127.0.0.1:8000/docs

## Security note
This is a research/demo prototype. It is not production banking software. The WebAuthn browser ceremony is real, but production use requires server-side credential/challenge verification, persistent credential storage, HTTPS, account binding, replay protection and a maintained WebAuthn library.
