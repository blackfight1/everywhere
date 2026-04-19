package payload

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadFromYAML(path string) ([]Payload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var file File
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file.Payloads, nil
}

func LoadFromCSV(path string) ([]Payload, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var items []Payload
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "# ") {
			continue
		}
		item, err := ParseCSVLine(line)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}

func ParseCSVLine(line string) (Payload, error) {
	active := true
	switch {
	case strings.HasPrefix(line, "#"):
		active = false
		line = strings.TrimPrefix(line, "#")
	case strings.HasPrefix(line, "0,"):
		active = false
		line = strings.TrimPrefix(line, "0,")
	case strings.HasPrefix(line, "1,"):
		active = true
		line = strings.TrimPrefix(line, "1,")
	}

	parts := strings.SplitN(line, ",", 3)
	if len(parts) != 3 {
		return Payload{}, fmt.Errorf("invalid csv payload: %q", line)
	}

	return Payload{
		Active: active,
		Type:   Type(strings.TrimSpace(parts[0])),
		Key:    strings.TrimSpace(parts[1]),
		Value:  strings.TrimSpace(parts[2]),
		Group:  "imported",
	}, nil
}

func ToCSV(items []Payload) string {
	var builder strings.Builder
	for _, item := range items {
		prefix := "1,"
		if !item.Active {
			prefix = "0,"
		}
		builder.WriteString(prefix)
		builder.WriteString(string(item.Type))
		builder.WriteString(",")
		builder.WriteString(item.Key)
		builder.WriteString(",")
		builder.WriteString(item.Value)
		builder.WriteString("\n")
	}
	return builder.String()
}
