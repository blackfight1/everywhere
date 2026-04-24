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
		api.GET("/auth/session", server.getSession)
		api.POST("/auth/login", server.login)
		api.POST("/auth/logout", server.logout)

		private := api.Group("")
		private.Use(server.authRequired())
		{
			private.POST("/scan", server.createScan)
			private.GET("/scans", server.listScans)
			private.GET("/scan/:id", server.getScan)
			private.POST("/scan/:id/stop", server.stopScan)
			private.GET("/scan/:id/results", server.getScanResults)
			private.DELETE("/scan/:id", server.deleteScan)

			private.GET("/payloads", server.listPayloads)
			private.PUT("/payloads", server.updatePayloads)
			private.PUT("/payloads/:id", server.updatePayload)
			private.POST("/payloads/import", server.importPayloads)
			private.GET("/payloads/export", server.exportPayloads)

			private.GET("/pingbacks", server.listPingbacks)
			private.GET("/pingbacks/:id", server.getPingback)
			private.GET("/stats", server.getStats)
			private.GET("/settings", server.getSettings)
			private.PUT("/settings", server.updateSettings)
			private.POST("/settings/notification/test", server.testNotification)
			private.GET("/ws", server.handleWS)
		}
	}

	return router
}
