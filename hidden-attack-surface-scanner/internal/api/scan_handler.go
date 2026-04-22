package api

import (
	"net/http"
	"time"

	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/scanner"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (s *Server) createScan(c *gin.Context) {
	var req scanner.StartScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := s.engine.StartScan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, task)
}

func (s *Server) listScans(c *gin.Context) {
	var tasks []database.ScanTask
	if err := s.db.Order("created_at desc").Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (s *Server) getScan(c *gin.Context) {
	var task database.ScanTask
	if err := s.db.First(&task, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan task not found"})
		return
	}
	c.JSON(http.StatusOK, task)
}

func (s *Server) stopScan(c *gin.Context) {
	if err := s.engine.StopScan(c.Param("id")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "stopping"})
}

func (s *Server) getScanResults(c *gin.Context) {
	query := s.db.Order("received_at desc").Where("scan_task_id = ?", c.Param("id"))
	rows, err := s.buildPingbackEvidence(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (s *Server) deleteScan(c *gin.Context) {
	taskID := c.Param("id")
	_ = s.engine.StopScan(taskID)

	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&database.Pingback{}, "scan_task_id = ?", taskID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&database.SentPayload{}, "scan_task_id = ?", taskID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&database.ScanTask{}, "id = ?", taskID).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted_at": time.Now().UTC()})
}
