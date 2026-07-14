package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/configcrate/port-map-check/internal/model"
)

func Write(writer io.Writer, value model.Report, format string) error {
	switch format {
	case "text":
		return writeText(writer, value)
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	case "html":
		return htmlReport.Execute(writer, value)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func writeText(writer io.Writer, value model.Report) error {
	if _, err := fmt.Fprintf(writer, "Port Map Check\nRoot: %s\n\n", value.Root); err != nil {
		return err
	}
	if len(value.Ports) == 0 {
		if _, err := fmt.Fprintln(writer, "No supported port declarations found."); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(writer, "Port map:"); err != nil {
			return err
		}
		for _, port := range value.Ports {
			mapping := displayPort(port)
			if _, err := fmt.Fprintf(writer, "  %-14s %-22s %-13s %-14s %s", port.Platform, port.Service, port.Kind, mapping, port.Source); err != nil {
				return err
			}
			if port.Line > 0 {
				if _, err := fmt.Fprintf(writer, ":%d", port.Line); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
	}
	if len(value.Findings) > 0 {
		if _, err := fmt.Fprintln(writer, "\nFindings:"); err != nil {
			return err
		}
		for _, finding := range value.Findings {
			marker := "WARN"
			if finding.Severity == model.SeverityError {
				marker = "ERROR"
			}
			location := finding.Source
			if finding.Line > 0 {
				location += fmt.Sprintf(":%d", finding.Line)
			}
			if location != "" {
				location = " (" + location + ")"
			}
			if _, err := fmt.Fprintf(writer, "  %s [%s]%s %s\n", marker, finding.Code, location, finding.Message); err != nil {
				return err
			}
			if finding.Suggestion != "" {
				if _, err := fmt.Fprintf(writer, "    fix: %s\n", finding.Suggestion); err != nil {
					return err
				}
			}
		}
	}
	_, err := fmt.Fprintf(writer, "\nSummary: files=%d resources=%d ports=%d references=%d errors=%d warnings=%d\n", value.Summary.FilesScanned, value.Summary.Resources, value.Summary.Ports, value.Summary.References, value.Summary.Errors, value.Summary.Warnings)
	return err
}

func displayPort(port model.Port) string {
	protocol := port.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	if port.TargetName != "" {
		return fmt.Sprintf("%d→%s/%s", port.Published, port.TargetName, protocol)
	}
	if port.Published != 0 && port.Target != 0 && port.Published != port.Target {
		return fmt.Sprintf("%d→%d/%s", port.Published, port.Target, protocol)
	}
	return fmt.Sprintf("%d/%s", port.DisplayPort(), protocol)
}

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{
	"displayPort": displayPort,
	"shortTime":   func(value time.Time) string { return value.Format("2006-01-02 15:04 UTC") },
	"isError":     func(value model.Severity) bool { return value == model.SeverityError },
	"location": func(source string, line int) string {
		if line > 0 {
			return fmt.Sprintf("%s:%d", source, line)
		}
		return source
	},
	"profiles": func(values []string) string { return strings.Join(values, ", ") },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Port Map Check report</title><style>
:root{color-scheme:dark;--bg:#08111d;--panel:#101d2d;--line:#26384f;--text:#eef6ff;--muted:#92a5bb;--cyan:#4ed4d0;--blue:#70a7ff;--red:#ff6d7c;--yellow:#ffd166;--green:#57d6a2}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#12304a 0,#08111d 38%);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}.wrap{max-width:1260px;margin:auto;padding:42px 24px 80px}h1{font-size:36px;margin:0}h2{font-size:20px;margin:36px 0 14px}.sub,.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(6,minmax(120px,1fr));gap:12px;margin:28px 0}.card,.panel{background:rgba(16,29,45,.94);border:1px solid var(--line);border-radius:14px}.card{padding:18px}.card b{display:block;font-size:28px}.card span{color:var(--muted)}.bad{color:var(--red)}.warn{color:var(--yellow)}.good{color:var(--green)}.panel{padding:10px 18px;overflow:auto}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line)}th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}code{color:var(--cyan)}.pill{display:inline-block;padding:3px 8px;border-radius:99px;background:#20354e;color:#d7e7ff;font-size:12px}.finding{padding:14px 16px;border-left:4px solid var(--yellow);background:rgba(255,209,102,.08);margin:9px 0;border-radius:8px}.finding.error{border-color:var(--red);background:rgba(255,109,124,.08)}.fix{color:var(--muted);margin-top:4px}.footer{margin-top:42px;color:var(--muted)}a{color:var(--blue)}@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main class="wrap">
<h1>Port Map Check</h1><div class="sub">Repository port topology · generated {{shortTime .GeneratedAt}}</div>
<div class="cards"><div class="card"><b>{{.Summary.Resources}}</b><span>resources</span></div><div class="card"><b>{{.Summary.Ports}}</b><span>ports</span></div><div class="card"><b>{{.Summary.References}}</b><span>URL references</span></div><div class="card"><b class="bad">{{.Summary.Errors}}</b><span>errors</span></div><div class="card"><b class="warn">{{.Summary.Warnings}}</b><span>warnings</span></div><div class="card"><b>{{.Summary.FilesScanned}}</b><span>files scanned</span></div></div>
<h2>Findings</h2>{{if .Findings}}{{range .Findings}}<div class="finding {{if isError .Severity}}error{{end}}"><strong>{{.Severity}}</strong> · <code>{{.Code}}</code>{{if .Source}} · {{location .Source .Line}}{{end}}<br>{{.Message}}{{if .Suggestion}}<div class="fix">Suggested fix: {{.Suggestion}}</div>{{end}}</div>{{end}}{{else}}<div class="panel good">No port-topology problems found.</div>{{end}}
<h2>Port map</h2><div class="panel"><table><thead><tr><th>Platform</th><th>Resource</th><th>Kind</th><th>Mapping</th><th>Bind</th><th>Profiles</th><th>Source</th></tr></thead><tbody>{{range .Ports}}<tr><td><span class="pill">{{.Platform}}</span></td><td>{{.Service}}</td><td>{{.Kind}}</td><td><code>{{displayPort .}}</code></td><td>{{.HostIP}}</td><td>{{profiles .Profiles}}</td><td>{{location .Source .Line}}</td></tr>{{end}}</tbody></table></div>
<h2>Detected references</h2><div class="panel"><table><thead><tr><th>Owner</th><th>Context</th><th>Destination</th><th>Platform</th><th>Source</th></tr></thead><tbody>{{range .References}}<tr><td>{{.Owner}}</td><td>{{.Context}}</td><td><code>{{.Host}}:{{if .PortName}}{{.PortName}}{{else}}{{.Port}}{{end}}</code></td><td><span class="pill">{{.Platform}}</span></td><td>{{location .Source .Line}}</td></tr>{{end}}</tbody></table></div>
<div class="footer">Static analysis only: no containers or workloads were started. Built by <a href="https://configcrate.com/">ConfigCrate</a>.</div>
</main></body></html>`))
