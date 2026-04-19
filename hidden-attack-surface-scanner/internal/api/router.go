package api

import (
	"net/http"

	appconfig "hidden-attack-surface-scanner/internal/config"
	"hidden-attack-surface-scanner/pkg/scanner"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Server struct {
	db     *gorm.DB
	cfg    *appconfig.Config
	engine *scanner.Engine
	hub    *Hub
}

func NewRouter(db *gorm.DB, cfg *appconfig.Config, engine *scanner.Engine, hub *Hub) *gin.Engine {
	server := &Server{
		db:     db,
		cfg:    cfg,
		engine: engine,
		hub:    hub,
	}

	router := gin.Default()
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := router.Group("/api")
	{
		api.POST("/scan", server.createScan)
		api.GET("/scans", server.listScans)
		api.GET("/scan/:id", server.getScan)
		api.POST("/scan/:id/stop", server.stopScan)
		api.GET("/scan/:id/results", server.getScanResults)
		api.DELETE("/scan/:id", server.deleteScan)

		api.GET("/payloads", server.listPayloads)
		api.PUT("/payloads", server.updatePayloads)
		api.PUT("/payloads/:id", server.updatePayload)
		api.POST("/payloads/import", server.importPayloads)
		api.GET("/payloads/export", server.exportPayloads)

		api.GET("/pingbacks", server.listPingbacks)
		api.GET("/pingbacks/:id", server.getPingback)
		api.GET("/stats", server.getStats)
		api.GET("/settings", server.getSettings)
		api.PUT("/settings", server.updateSettings)
		api.GET("/ws", server.handleWS)
	}

	return router
}
