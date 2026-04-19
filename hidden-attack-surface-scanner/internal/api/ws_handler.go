package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) handleWS(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	s.hub.Add(conn)
	defer func() {
		s.hub.Remove(conn)
		conn.Close()
	}()

	_ = conn.WriteJSON(gin.H{
		"type": "connected",
		"time": time.Now().UTC(),
	})

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
