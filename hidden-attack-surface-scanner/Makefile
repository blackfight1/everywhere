build:
	cd frontend && npm install && npm run build
	go build -o scanner ./cmd/server

run:
	go run ./cmd/server -config configs/config.yaml -payloads configs/injections.yaml

docker-up:
	docker compose up -d --build
