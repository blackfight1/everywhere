package database

import (
	"fmt"

	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/pkg/payload"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Open(cfg appconfig.Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.PostgresDSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.AutoMigrate(&ScanTask{}, &PayloadTemplate{}, &SentPayload{}, &Pingback{}); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return db, nil
}

func SeedPayloads(db *gorm.DB, items []payload.Payload) error {
	var count int64
	if err := db.Model(&PayloadTemplate{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	records := make([]PayloadTemplate, 0, len(items))
	for idx, item := range items {
		records = append(records, PayloadTemplate{
			Active:   item.Active,
			Type:     string(item.Type),
			Key:      item.Key,
			Value:    item.Value,
			Group:    item.Group,
			Comment:  item.Comment,
			Position: idx,
		})
	}
	return db.Create(&records).Error
}
