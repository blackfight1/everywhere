# Hidden Attack Surface Scanner

Web project that automates the core workflow of `collaborator-everywhere-v2` without Burp Suite.

## Features

- Standard header and parameter payload injection
- Raw request variants inspired by `Cracking the Lens`
- Interactsh polling and correlation
- PostgreSQL persistence for scans, payloads, sent payloads, and pingbacks
- REST API plus WebSocket notifications
- Minimal Vue dashboard
- Docker Compose deployment

## Run

```bash
cp .env.example .env
docker compose up -d --build
```

Backend API defaults to `http://localhost:8080`, frontend to `http://localhost`.
