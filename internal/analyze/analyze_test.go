package analyze

import (
	"path/filepath"
	"testing"

	"github.com/configcrate/port-map-check/internal/scan"
)

func TestBrokenStackFindings(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "broken-stack")
	input, err := scan.Repository(root, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	report := Build(root, input)
	want := map[string]bool{
		"compose-duplicate-host-port":    false,
		"compose-healthcheck-host-port":  false,
		"compose-service-uses-host-port": false,
		"dockerfile-expose-mismatch":     false,
		"k8s-duplicate-node-port":        false,
		"k8s-ingress-port-mismatch":      false,
		"k8s-probe-port-mismatch":        false,
		"k8s-service-no-workload":        false,
		"k8s-target-name-mismatch":       false,
	}
	for _, finding := range report.Findings {
		if _, ok := want[finding.Code]; ok {
			want[finding.Code] = true
		}
	}
	for code, found := range want {
		if !found {
			t.Errorf("missing finding %s", code)
		}
	}
	if report.Summary.Errors != 6 || report.Summary.Warnings != 3 {
		t.Fatalf("summary errors=%d warnings=%d, want 6/3", report.Summary.Errors, report.Summary.Warnings)
	}
}

func TestHealthyStackHasNoFindings(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "healthy-stack")
	input, err := scan.Repository(root, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	report := Build(root, input)
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %#v, want none", report.Findings)
	}
}

func TestHostBindingsOverlap(t *testing.T) {
	tests := []struct {
		left, right string
		want        bool
	}{
		{"0.0.0.0", "127.0.0.1", true},
		{"127.0.0.1", "192.168.1.2", false},
		{"::", "::1", true},
		{"0.0.0.0", "::1", false},
	}
	for _, test := range tests {
		if got := hostBindingsOverlap(test.left, test.right); got != test.want {
			t.Errorf("hostBindingsOverlap(%q,%q) = %v, want %v", test.left, test.right, got, test.want)
		}
	}
}
