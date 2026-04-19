package main

import (
	"flag"
	"log"

	"hidden-attack-surface-scanner/internal/api"
	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/payload"
	"hidden-attack-surface-scanner/pkg/scanner"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	payloadPath := flag.String("payloads", "configs/injections.yaml", "path to payload config")
	flag.Parse()

	cfg, err := appconfig.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := database.Open(cfg)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	payloads, err := payload.LoadFromYAML(*payloadPath)
	if err != nil {
		log.Fatalf("load payloads: %v", err)
	}
	if err := database.SeedPayloads(db, payloads); err != nil {
		log.Fatalf("seed payloads: %v", err)
	}

	hub := api.NewHub()
	engine := scanner.NewEngine(db, cfg, hub)
	router := api.NewRouter(db, &cfg, engine, hub)

	log.Printf("listening on %s", cfg.Server.Listen)
	if err := router.Run(cfg.Server.Listen); err != nil {
		log.Fatalf("run server: %v", err)
	}
}
