package correlator

import "strings"

func EvaluateSeverity(protocol string, fromOwnIP bool, ownIPAction string) string {
	if fromOwnIP {
		switch strings.ToLower(ownIPAction) {
		case "drop":
			return ""
		case "downgrade":
			return "low"
		default:
			return "low"
		}
	}

	switch strings.ToLower(protocol) {
	case "http", "https":
		return "high"
	case "smtp", "ftp":
		return "high"
	case "ldap":
		return "critical"
	case "dns":
		return "medium"
	default:
		return "medium"
	}
}
