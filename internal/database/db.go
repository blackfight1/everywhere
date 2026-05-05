package database

import (
	"fmt"

	appconfig "github.com/blackfight1/everywhere/internal/config"
	"github.com/blackfight1/everywhere/pkg/payload"

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
	if err := db.AutoMigrate(&ScanTask{}, &PayloadTemplate{}, &SentPayload{}, &Pingback{}, &ResponseFinding{}, &NotificationState{}, &TargetSet{}, &TargetRecord{}, &TargetImportJob{}); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	if err := migratePingbackIndexes(db); err != nil {
		return nil, fmt.Errorf("migrate pingback indexes: %w", err)
	}
	return db, nil
}

func migratePingbackIndexes(db *gorm.DB) error {
	statements := []string{
		`DROP INDEX IF EXISTS idx_pingbacks_unique_id`,
		`DROP INDEX IF EXISTS pingbacks_unique_id_key`,
		`ALTER TABLE pingbacks DROP CONSTRAINT IF EXISTS pingbacks_unique_id_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_pingbacks_uid_proto ON pingbacks (unique_id, callback_protocol)`,
	}
	for _, stmt := range statements {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
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

func SyncPayloads(db *gorm.DB, items []payload.Payload) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&PayloadTemplate{}).Error; err != nil {
			return err
		}

		if len(items) == 0 {
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
		return tx.Create(&records).Error
	})
}
