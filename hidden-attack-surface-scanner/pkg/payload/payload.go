package payload

type Type string

const (
	TypeHeader Type = "header"
	TypeParam  Type = "param"
	TypeRaw    Type = "raw"
)

type Payload struct {
	ID      string `json:"id" yaml:"id"`
	Active  bool   `json:"active" yaml:"active"`
	Type    Type   `json:"type" yaml:"type"`
	Key     string `json:"key" yaml:"key"`
	Value   string `json:"value" yaml:"value"`
	Group   string `json:"group" yaml:"group"`
	Comment string `json:"comment" yaml:"comment"`
}

type File struct {
	Payloads []Payload `yaml:"payloads"`
}

type ResolveOptions struct {
	Host           string
	DefaultOrigin  string
	DefaultReferer string
}

type ResolvedPayload struct {
	Payload
	ResolvedValue string `json:"resolved_value"`
}
