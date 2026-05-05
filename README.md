# Everywhere CLI

Small command-line OOB scanner for hidden HTTPS attack surface discovery.

## What It Scans

The tool now scans only 4 core raw payload types:

1. `absolute-url-host-mismatch`
2. `duplicate-host`
3. `host-with-at`
4. `host-at-reversed`

Everything else has been removed from the default workflow.

## Install

Install with `go install`:

```bash
go install github.com/blackfight1/everywhere/cmd/everywhere@latest
```

Update later:

```bash
everywhere update
```

Or:

```bash
go build -o everywhere ./cmd/everywhere
```

## Simple Usage

Single target:

```bash
everywhere scan -target https://example.com
```

Target file:

```bash
everywhere scan -targets-file targets.txt
```

JSON summary:

```bash
everywhere scan -targets-file targets.txt -json-summary
```

## Useful Flags

- `-target`
- `-targets-file`
- `-concurrency`
- `-batch-size`
- `-rate-limit`
- `-callback-timeout`
- `-proxy`
- `-interactsh-server`
- `-interactsh-token`
- `-json-summary`

## Defaults

If you do not override them, the scanner uses:

- config: `~/.config/everywhere/config.yaml`
- payloads: `~/.config/everywhere/payloads.yaml`
- mode: raw-only

The first CLI run will create these YAML files automatically.

## Docker Compose

`docker-compose.yml` runs:

- `postgres`
- `scanner`

Default container command expects:

- config at `/opt/everywhere-data/config.yaml`
- targets at `/opt/everywhere-data/targets.txt`

Start:

```bash
docker compose up -d --build
```

Follow logs:

```bash
docker logs -f everywhere-cli
```
