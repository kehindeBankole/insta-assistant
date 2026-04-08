# insta-assistant

Go webhook server for Instagram DM auto-replies with conversation memory and follow-ups.

## Features
- `GET /ig-webhook` for Meta webhook verification
- `POST /ig-webhook` for Instagram messaging events
- Signature verification via `X-Hub-Signature-256` (when `IG_APP_SECRET` is set)
- Conversation memory (last `MEMORY_TURNS` turns per sender)
- Auto follow-up worker (`FOLLOWUP_DELAY`, max per user)
- Persistent local storage via BoltDB (`insta-assistant.db`)

## Quick start
```bash
cp .env.example .env
# fill secrets in .env

export $(grep -v '^#' .env | xargs)
go mod tidy
go run .
```

Server starts on `PORT` (default `8080`).

## Meta webhook setup
- Callback URL: `https://<your-domain>/ig-webhook`
- Verify token: `IG_VERIFY_TOKEN`

## Environment variables
See `.env.example`.

## Health check
`GET /health` -> `ok`
