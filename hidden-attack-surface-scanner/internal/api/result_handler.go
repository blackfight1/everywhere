package api

import (
	"net/http"

	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/internal/database"

	"github.com/gin-gonic/gin"
)

func (s *Server) listPingbacks(c *gin.Context) {
	var rows []database.Pingback
	query := s.db.Order("received_at desc")

	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if protocol := c.Query("protocol"); protocol != "" {
		query = query.Where("callback_protocol = ?", protocol)
	}
	if taskID := c.Query("scan_task_id"); taskID != "" {
		query = query.Where("scan_task_id = ?", taskID)
	}

	if err := query.Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

func (s *Server) getPingback(c *gin.Context) {
	var row database.Pingback
	if err := s.db.First(&row, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "pingback not found"})
		return
	}
	c.JSON(http.StatusOK, row)
}

func (s *Server) getStats(c *gin.Context) {
	var scanCount, activeCount, pingbackCount int64
	s.db.Model(&database.ScanTask{}).Count(&scanCount)
	s.db.Model(&database.ScanTask{}).Where("status IN ?", []string{"running", "waiting_callback"}).Count(&activeCount)
	s.db.Model(&database.Pingback{}).Count(&pingbackCount)

	var recent []database.Pingback
	s.db.Order("received_at desc").Limit(10).Find(&recent)

	c.JSON(http.StatusOK, gin.H{
		"scan_count":     scanCount,
		"active_count":   activeCount,
		"pingback_count": pingbackCount,
		"recent":         recent,
	})
}

func (s *Server) getSettings(c *gin.Context) {
	c.JSON(http.StatusOK, s.cfg)
}

func (s *Server) updateSettings(c *gin.Context) {
	var input appconfig.Config
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Interactsh.ServerURL != "" || input.Interactsh.Token != "" {
		s.cfg.Interactsh = input.Interactsh
	}
	if input.Scanner.DefaultConcurrency > 0 {
		s.cfg.Scanner = input.Scanner
	}
	if input.OwnIP.Action != "" {
		s.cfg.OwnIP.Action = input.OwnIP.Action
	}

	c.JSON(http.StatusOK, s.cfg)
}
