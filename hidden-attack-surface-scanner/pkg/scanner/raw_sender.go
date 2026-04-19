package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type RawRequest struct {
	Address  string
	UseTLS   bool
	SNIHost  string
	RawBytes []byte
}

func SendRawRequest(ctx context.Context, req RawRequest, timeout time.Duration) (int, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", req.Address)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if req.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         req.SNIHost,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return 0, err
		}
		if err := tlsConn.Handshake(); err != nil {
			return 0, err
		}
		conn = tlsConn
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	if _, err := conn.Write(req.RawBytes); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return 0, err
	}

	if statusLine == "" {
		return 0, nil
	}

	parts := strings.Split(strings.TrimSpace(statusLine), " ")
	if len(parts) < 2 {
		return 0, nil
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("parse raw response status: %w", err)
	}
	return code, nil
}
