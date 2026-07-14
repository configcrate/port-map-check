package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/configcrate/port-map-check/internal/model"
)

func TestWriteFormats(t *testing.T) {
	value := model.Report{Root: "/repo", GeneratedAt: time.Unix(0, 0).UTC(), Ports: []model.Port{{Platform: model.PlatformCompose, Kind: model.PortPublished, Service: "api", Source: "compose.yaml", Published: 8080, Target: 3000, Protocol: "tcp"}}, Findings: []model.Finding{{Severity: model.SeverityError, Code: "example", Message: "broken", Suggestion: "fix it", Source: "compose.yaml"}}, Summary: model.Summary{Resources: 1, Ports: 1, Errors: 1}}
	for _, format := range []string{"text", "json", "html"} {
		var output bytes.Buffer
		if err := Write(&output, value, format); err != nil {
			t.Fatalf("Write(%s): %v", format, err)
		}
		if output.Len() == 0 {
			t.Fatalf("Write(%s) returned empty output", format)
		}
		if format == "html" && !strings.Contains(output.String(), "https://configcrate.com/") {
			t.Fatal("HTML report is missing the ConfigCrate link")
		}
	}
}
