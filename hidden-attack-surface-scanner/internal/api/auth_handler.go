package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const authSessionTTL = 24 * time.Hour

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
}

func (s *Server) authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, ok := s.readSession(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		c.Set("auth_username", username)
		c.Next()
	}
}

func (s *Server) getSession(c *gin.Context) {
	username, ok := s.readSession(c)
	if !ok {
		c.JSON(http.StatusOK, sessionResponse{Authenticated: false})
		return
	}
	c.JSON(http.StatusOK, sessionResponse{Authenticated: true, Username: username})
}

func (s *Server) login(c *gin.Context) {
	var input loginRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(input.Username)), []byte(s.cfg.Auth.Username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(input.Password), []byte(s.cfg.Auth.Password)) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	s.writeSession(c, s.cfg.Auth.Username)
	c.JSON(http.StatusOK, sessionResponse{Authenticated: true, Username: s.cfg.Auth.Username})
}

func (s *Server) logout(c *gin.Context) {
	s.clearSession(c)
	c.JSON(http.StatusOK, sessionResponse{Authenticated: false})
}

func (s *Server) writeSession(c *gin.Context, username string) {
	expiresAt := time.Now().UTC().Add(authSessionTTL).Unix()
	payload := fmt.Sprintf("%s|%d", username, expiresAt)
	signature := s.signSession(payload)
	token := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + signature))

	cookie := &http.Cookie{
		Name:     s.cfg.Auth.CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(authSessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsSecure(c.Request),
	}
	http.SetCookie(c.Writer, cookie)
}

func (s *Server) clearSession(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     s.cfg.Auth.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsSecure(c.Request),
	}
	http.SetCookie(c.Writer, cookie)
}

func (s *Server) readSession(c *gin.Context) (string, bool) {
	token, err := c.Cookie(s.cfg.Auth.CookieName)
	if err != nil || strings.TrimSpace(token) == "" {
		return "", false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}

	parts := strings.Split(string(decoded), "|")
	if len(parts) != 3 {
		return "", false
	}

	username := parts[0]
	expiresAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", false
	}
	if time.Now().UTC().Unix() > expiresAt {
		return "", false
	}

	payload := strings.Join(parts[:2], "|")
	expectedSig := s.signSession(payload)
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.Auth.Username)) != 1 {
		return "", false
	}

	return username, true
}

func (s *Server) signSession(payload string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Auth.SessionSecret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func requestIsSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
