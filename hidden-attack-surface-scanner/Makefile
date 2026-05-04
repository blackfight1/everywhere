build:
	go build -o everywhere ./cmd/everywhere

run:
	go run ./cmd/everywhere -config configs/config.yaml -payloads configs/injections.yaml

docker-up:
	docker compose up -d --build
