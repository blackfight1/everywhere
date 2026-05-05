package payload

import "testing"

func TestResolvePayloadWithDefaults(t *testing.T) {
	item := Payload{
		Type:  TypeHeader,
		Key:   "Origin",
		Value: "https://%o.%s",
	}

	resolved, ok := Resolve(item, "abc.oast.pro", ResolveOptions{
		Host:          "example.com",
		DefaultOrigin: "app.example.com",
	})
	if !ok {
		t.Fatalf("expected payload to resolve")
	}
	if resolved.ResolvedValue != "https://app.example.com.abc.oast.pro" {
		t.Fatalf("unexpected value: %s", resolved.ResolvedValue)
	}
}

func TestResolvePayloadSkipsWhenRefererMissing(t *testing.T) {
	item := Payload{
		Type:  TypeHeader,
		Key:   "Referer",
		Value: "https://%r.%s",
	}

	_, ok := Resolve(item, "abc.oast.pro", ResolveOptions{Host: "example.com"})
	if ok {
		t.Fatalf("expected payload to be skipped when referer is missing")
	}
}
