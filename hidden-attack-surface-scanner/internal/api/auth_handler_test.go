package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appconfig "hidden-attack-surface-scanner/internal/config"

	"github.com/gin-gonic/gin"
)

func TestLoginSessionLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &appconfig.Config{
		Auth: appconfig.AuthConfig{
			Username:      "leftshoulder",
			Password:      "yy233966",
			SessionSecret: "test-secret",
			CookieName:    "hass_session",
		},
	}

	server := &Server{cfg: cfg}
	router := gin.New()
	router.GET("/session", server.getSession)
	router.POST("/login", server.login)
	router.POST("/logout", server.logout)

	protected := router.Group("")
	protected.Use(server.authRequired())
	protected.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated protected status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	body, _ := json.Marshal(loginRequest{Username: "leftshoulder", Password: "yy233966"})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d", rec.Code, http.StatusOK)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	req = httptest.NewRequest(http.MethodGet, "/session", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got == "" || !bytes.Contains(rec.Body.Bytes(), []byte(`"authenticated":true`)) {
		t.Fatalf("session body = %s, want authenticated true", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated protected status = %d, want %d", rec.Code, http.StatusOK)
	}

	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want %d", rec.Code, http.StatusOK)
	}
}
