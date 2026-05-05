package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
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

type RawResponse struct {
	StatusCode  int
	StatusLine  string
	Headers     textproto.MIMEHeader
	BodyExcerpt string
	RawExcerpt  string
}

func SendRawRequest(ctx context.Context, req RawRequest, timeout time.Duration) (int, error) {
	resp, err := SendRawRequestDetailed(ctx, req, timeout)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

func SendRawRequestDetailed(ctx context.Context, req RawRequest, timeout time.Duration) (RawResponse, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", req.Address)
	if err != nil {
		return RawResponse{}, err
	}
	defer conn.Close()

	if req.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         req.SNIHost,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return RawResponse{}, err
		}
		if err := tlsConn.Handshake(); err != nil {
			return RawResponse{}, err
		}
		conn = tlsConn
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return RawResponse{}, err
	}
	if _, err := conn.Write(req.RawBytes); err != nil {
		return RawResponse{}, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return RawResponse{}, err
	}

	if statusLine == "" {
		return RawResponse{}, nil
	}

	parts := strings.Split(strings.TrimSpace(statusLine), " ")
	if len(parts) < 2 {
		return RawResponse{
			StatusLine: strings.TrimSpace(statusLine),
			RawExcerpt: strings.TrimSpace(statusLine),
		}, nil
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return RawResponse{}, fmt.Errorf("parse raw response status: %w", err)
	}

	remainder, _ := io.ReadAll(io.LimitReader(reader, 4096))
	headers := make(textproto.MIMEHeader)
	bodyBytes := remainder
	if headerBlock, bodyBlock, ok := splitRawHTTPPayload(remainder); ok {
		if parsed := parseMIMEHeader(headerBlock); len(parsed) > 0 {
			headers = parsed
			bodyBytes = bodyBlock
		}
	}
	bodyExcerpt := sanitizeExcerpt(bodyBytes)

	var raw bytes.Buffer
	raw.WriteString(strings.TrimRight(statusLine, "\r\n"))
	raw.WriteString("\r\n")
	for _, line := range renderHeaderLines(headers) {
		raw.WriteString(line)
		raw.WriteString("\r\n")
	}
	if len(headers) > 0 {
		raw.WriteString("\r\n")
	}
	raw.Write(bodyBytes)

	return RawResponse{
		StatusCode:  code,
		StatusLine:  strings.TrimSpace(statusLine),
		Headers:     headers,
		BodyExcerpt: bodyExcerpt,
		RawExcerpt:  sanitizeExcerpt(raw.Bytes()),
	}, nil
}

func sanitizeExcerpt(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	clean := bytes.Map(func(r rune) rune {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			return r
		case r >= 32 && r < 127:
			return r
		default:
			return -1
		}
	}, data)
	return strings.TrimSpace(string(clean))
}

func headerString(header textproto.MIMEHeader) string {
	return strings.Join(renderHeaderLines(header), "\n")
}

func splitRawHTTPPayload(data []byte) ([]byte, []byte, bool) {
	if len(data) == 0 {
		return nil, nil, false
	}
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
		return data[:idx], data[idx+4:], true
	}
	if idx := bytes.Index(data, []byte("\n\n")); idx >= 0 {
		return data[:idx], data[idx+2:], true
	}
	return nil, nil, false
}

func parseMIMEHeader(data []byte) textproto.MIMEHeader {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(data, []byte("\r\n\r\n")...))))
	header, err := reader.ReadMIMEHeader()
	if err != nil {
		return nil
	}
	return header
}

func renderHeaderLines(header textproto.MIMEHeader) []string {
	if len(header) == 0 {
		return nil
	}
	lines := make([]string, 0, len(header))
	for key, values := range header {
		for _, value := range values {
			lines = append(lines, key+": "+value)
		}
	}
	return lines
}
