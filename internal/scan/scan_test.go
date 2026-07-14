package scan

import (
	"bytes"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRepositoryFindsSupportedConfiguration(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "broken-stack")
	result, err := Repository(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 3 {
		t.Fatalf("FilesScanned = %d, want 3", result.FilesScanned)
	}
	if len(result.Resources) != 8 {
		t.Fatalf("resources = %d, want 8", len(result.Resources))
	}
	if len(result.Ports) != 10 {
		t.Fatalf("ports = %d, want 10", len(result.Ports))
	}
	if len(result.References) != 4 {
		t.Fatalf("references = %d, want 4", len(result.References))
	}
}

func TestParseComposeShortPort(t *testing.T) {
	tests := []struct {
		value             string
		host              string
		published, target int
		protocol          string
	}{
		{"8080:80", "", 8080, 80, "tcp"},
		{"127.0.0.1:8443:443/tcp", "127.0.0.1", 8443, 443, "tcp"},
		{"[::1]:5353:53/udp", "::1", 5353, 53, "udp"},
		{"3000", "", 0, 3000, "tcp"},
	}
	for _, test := range tests {
		host, published, target, protocol := parseComposeShortPort(test.value)
		if host != test.host || published != test.published || target != test.target || protocol != test.protocol {
			t.Errorf("parseComposeShortPort(%q) = %q,%d,%d,%q", test.value, host, published, target, protocol)
		}
	}
}

func TestStripJSONCommentsPreservesStrings(t *testing.T) {
	input := []byte("{\n// comment\n\"url\":\"http://localhost:3000\",/* block */\"port\":3000\n}")
	value := string(stripJSONComments(input))
	if value != "{\n\n\"url\":\"http://localhost:3000\",\"port\":3000\n}" {
		t.Fatalf("unexpected cleaned JSON: %q", value)
	}
}

func TestStripTrailingJSONCommas(t *testing.T) {
	input := []byte("{\"ports\":[3000,],\"name\":\"comma,}\",}")
	got := string(stripTrailingJSONCommas(input))
	want := "{\"ports\":[3000],\"name\":\"comma,}\"}"
	if got != want {
		t.Fatalf("stripTrailingJSONCommas = %q, want %q", got, want)
	}
}

func TestRepositoryExcludeGlob(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "broken-stack")
	result, err := Repository(root, Options{Exclude: []string{"k8s/**", "api/Dockerfile"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 1 {
		t.Fatalf("FilesScanned = %d, want 1", result.FilesScanned)
	}
}

func TestMapNodeResolvesYAMLMerge(t *testing.T) {
	data := []byte("base: &base\n  ports: [\"8080:80\"]\nservice:\n  <<: *base\n")
	var document yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&document); err != nil {
		t.Fatal(err)
	}
	service := mapNode(document.Content[0], "service")
	ports := mapNode(service, "ports")
	if ports == nil || len(ports.Content) != 1 || ports.Content[0].Value != "8080:80" {
		t.Fatalf("merge was not resolved: %#v", ports)
	}
}
