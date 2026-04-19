package api

import (
	"net/http"
	"os"
	"strings"

	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/payload"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (s *Server) listPayloads(c *gin.Context) {
	var rows []database.PayloadTemplate
	if err := s.db.Order("position asc").Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (s *Server) updatePayloads(c *gin.Context) {
	var rows []database.PayloadTemplate
	if err := c.ShouldBindJSON(&rows); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
		seenIDs := make(map[string]struct{}, len(rows))
		for idx, row := range rows {
			row.Position = idx
			if row.ID != "" {
				seenIDs[row.ID] = struct{}{}
			}
			if row.ID == "" {
				if err := tx.Create(&row).Error; err != nil {
					return err
				}
				seenIDs[row.ID] = struct{}{}
				continue
			}
			if err := tx.Save(&row).Error; err != nil {
				return err
			}
		}

		var existingIDs []string
		if err := tx.Model(&database.PayloadTemplate{}).Pluck("id", &existingIDs).Error; err != nil {
			return err
		}
		for _, existingID := range existingIDs {
			if _, ok := seenIDs[existingID]; ok {
				continue
			}
			if err := tx.Delete(&database.PayloadTemplate{}, "id = ?", existingID).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": len(rows)})
}

func (s *Server) updatePayload(c *gin.Context) {
	var payloadRow database.PayloadTemplate
	if err := s.db.First(&payloadRow, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "payload not found"})
		return
	}

	if err := c.ShouldBindJSON(&payloadRow); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Save(&payloadRow).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, payloadRow)
}

func (s *Server) importPayloads(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tempPath := os.TempDir() + string(os.PathSeparator) + file.Filename
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tempPath)

	var items []payload.Payload
	switch {
	case strings.HasSuffix(strings.ToLower(file.Filename), ".yaml"), strings.HasSuffix(strings.ToLower(file.Filename), ".yml"):
		items, err = payload.LoadFromYAML(tempPath)
	default:
		items, err = payload.LoadFromCSV(tempPath)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&database.PayloadTemplate{}).Error; err != nil {
			return err
		}
		for idx, item := range items {
			row := database.PayloadTemplate{
				ID:       item.ID,
				Active:   item.Active,
				Type:     string(item.Type),
				Key:      item.Key,
				Value:    item.Value,
				Group:    item.Group,
				Comment:  item.Comment,
				Position: idx,
			}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"imported": len(items)})
}

func (s *Server) exportPayloads(c *gin.Context) {
	var rows []database.PayloadTemplate
	if err := s.db.Order("position asc").Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]payload.Payload, 0, len(rows))
	for _, row := range rows {
		items = append(items, payload.Payload{
			ID:      row.ID,
			Active:  row.Active,
			Type:    payload.Type(row.Type),
			Key:     row.Key,
			Value:   row.Value,
			Group:   row.Group,
			Comment: row.Comment,
		})
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="payloads.csv"`)
	c.String(http.StatusOK, payload.ToCSV(items))
}
