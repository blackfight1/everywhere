# Everywhere CLI

Command-line OOB scanner for hidden HTTPS attack surface discovery, inspired by `collaborator-everywhere-v2` and `Cracking the Lens`.

## Current Scope

- No frontend
- No REST API
- Single CLI binary
- PostgreSQL persistence for:
  - scan tasks
  - payload templates
  - sent payloads
  - pingbacks
  - notification state
- Interactsh polling and correlation
- Feishu notifications for findings and runtime failures

## Supported Payload Types

- `param`
- `raw`

The scanner no longer sends `header` payloads.

## Scan Modes

- `quick`
  - sends 6 high-value raw variants only
- `full`
  - sends every enabled `param` and `raw` payload

## Build

```bash
go build -o everywhere ./cmd/everywhere
```

## Run

Single target:

```bash
go run ./cmd/everywhere \
  -config configs/config.yaml \
  -payloads configs/injections.yaml \
  -target https://example.com \
  -mode quick
```

Target file:

```bash
go run ./cmd/everywhere \
  -config configs/config.yaml \
  -payloads configs/injections.yaml \
  -targets-file targets.txt \
  -mode quick \
  -batch-size 1500 \
  -rate-limit 20 \
  -callback-timeout 1440
```

JSON summary:

```bash
go run ./cmd/everywhere \
  -config configs/config.yaml \
  -payloads configs/injections.yaml \
  -targets-file targets.txt \
  -mode full \
  -json-summary
```

## Main Flags

- `-target`
- `-targets-file`
- `-mode`
- `-concurrency`
- `-batch-size`
- `-rate-limit`
- `-callback-timeout`
- `-proxy`
- `-default-origin`
- `-default-referer`
- `-interactsh-server`
- `-interactsh-token`
- `-json-summary`

## Docker Compose

`docker-compose.yml` now runs the CLI scanner container plus PostgreSQL.

Default container command expects:

- config at `/opt/everywhere-data/config.yaml`
- targets at `/opt/everywhere-data/targets.txt`

Start it with:

```bash
docker compose up -d --build
```

Follow logs with:

```bash
docker logs -f everywhere-cli
```
