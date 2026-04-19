package payload

import "strings"

func Resolve(item Payload, oobURL string, opts ResolveOptions) (ResolvedPayload, bool) {
	value := item.Value
	if strings.Contains(value, "%o") {
		if opts.DefaultOrigin == "" {
			return ResolvedPayload{}, false
		}
		value = strings.ReplaceAll(value, "%o", opts.DefaultOrigin)
	}
	if strings.Contains(value, "%r") {
		if opts.DefaultReferer == "" {
			return ResolvedPayload{}, false
		}
		value = strings.ReplaceAll(value, "%r", opts.DefaultReferer)
	}

	value = strings.ReplaceAll(value, "%s", oobURL)
	value = strings.ReplaceAll(value, "%h", opts.Host)

	return ResolvedPayload{
		Payload:       item,
		ResolvedValue: value,
	}, true
}

func ExpandRawTemplate(template string, host string, path string, oobURL string) string {
	value := strings.ReplaceAll(template, "{host}", host)
	value = strings.ReplaceAll(value, "{path}", path)
	value = strings.ReplaceAll(value, "%s", oobURL)
	return value
}
