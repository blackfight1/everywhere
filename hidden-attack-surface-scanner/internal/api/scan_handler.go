package api

import (
	"net/http"
	"strings"
	"time"

	"hidden-attack-surface-scanner/internal/database"
	"hidden-attack-surface-scanner/pkg/scanner"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type batchDeleteScanRequest struct {
	IDs []string `json:"ids"`
}

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

func (s *Server) deleteScans(c *gin.Context) {
	var req batchDeleteScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ids := normalizeScanIDs(req.IDs)
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids cannot be empty"})
		return
	}

	var tasks []database.ScanTask
	if err := s.db.Select("id", "status").Where("id IN ?", ids).Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	statusByID := make(map[string]string, len(tasks))
	for _, task := range tasks {
		statusByID[task.ID] = task.Status
	}

	deletable := make([]string, 0, len(ids))
	skipped := make([]gin.H, 0)
	for _, id := range ids {
		status, ok := statusByID[id]
		if !ok {
			skipped = append(skipped, gin.H{"id": id, "reason": "not_found"})
			continue
		}
		if !isFinishedScanStatus(status) {
			skipped = append(skipped, gin.H{"id": id, "reason": "status_" + strings.ToLower(strings.TrimSpace(status))})
			continue
		}
		deletable = append(deletable, id)
	}

	if len(deletable) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "no finished scans selected for deletion",
			"skipped":       skipped,
			"skipped_count": len(skipped),
		})
		return
	}

	if err := s.deleteScanRecords(deletable); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted_ids":   deletable,
		"deleted_count": len(deletable),
		"skipped":       skipped,
		"skipped_count": len(skipped),
		"deleted_at":    time.Now().UTC(),
	})
}

func (s *Server) deleteScan(c *gin.Context) {
	taskID := c.Param("id")
	if err := s.deleteScanRecords([]string{taskID}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted_at": time.Now().UTC()})
}

func (s *Server) deleteScanRecords(ids []string) error {
	ids = normalizeScanIDs(ids)
	if len(ids) == 0 {
		return nil
	}

	for _, id := range ids {
		_ = s.engine.StopScan(id)
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&database.NotificationState{}, "scan_task_id IN ?", ids).Error; err != nil {
			return err
		}
		if err := tx.Delete(&database.Pingback{}, "scan_task_id IN ?", ids).Error; err != nil {
			return err
		}
		if err := tx.Delete(&database.SentPayload{}, "scan_task_id IN ?", ids).Error; err != nil {
			return err
		}
		if err := tx.Delete(&database.ScanTask{}, "id IN ?", ids).Error; err != nil {
			return err
		}
		return nil
	})
}

func normalizeScanIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	normalized := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	return normalized
}

func isFinishedScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "failed", "stopped":
		return true
	default:
		return false
	}
}
