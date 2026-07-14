package model

import "time"

type Platform string

const (
	PlatformCompose      Platform = "docker-compose"
	PlatformKubernetes   Platform = "kubernetes"
	PlatformDockerfile   Platform = "dockerfile"
	PlatformDevContainer Platform = "devcontainer"
)

type Severity string

const (
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

type PortKind string

const (
	PortPublished PortKind = "published"
	PortContainer PortKind = "container"
	PortService   PortKind = "service"
	PortNode      PortKind = "node-port"
	PortExpose    PortKind = "expose"
	PortForward   PortKind = "forward"
)

type Port struct {
	ID         string            `json:"id"`
	Platform   Platform          `json:"platform"`
	Kind       PortKind          `json:"kind"`
	ResourceID string            `json:"resource_id"`
	Service    string            `json:"service"`
	Namespace  string            `json:"namespace,omitempty"`
	Source     string            `json:"source"`
	Line       int               `json:"line,omitempty"`
	HostIP     string            `json:"host_ip,omitempty"`
	Published  int               `json:"published,omitempty"`
	Target     int               `json:"target,omitempty"`
	TargetName string            `json:"target_name,omitempty"`
	Name       string            `json:"name,omitempty"`
	Protocol   string            `json:"protocol"`
	Profiles   []string          `json:"profiles,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func (p Port) DisplayPort() int {
	if p.Published != 0 {
		return p.Published
	}
	return p.Target
}

type Resource struct {
	ID        string            `json:"id"`
	Platform  Platform          `json:"platform"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Source    string            `json:"source"`
	Line      int               `json:"line,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Selector  map[string]string `json:"selector,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Reference struct {
	Platform   Platform `json:"platform"`
	ResourceID string   `json:"resource_id"`
	Owner      string   `json:"owner"`
	Namespace  string   `json:"namespace,omitempty"`
	Host       string   `json:"host"`
	Port       int      `json:"port,omitempty"`
	PortName   string   `json:"port_name,omitempty"`
	Scheme     string   `json:"scheme,omitempty"`
	Context    string   `json:"context"`
	Source     string   `json:"source"`
	Line       int      `json:"line,omitempty"`
}

type Finding struct {
	Severity   Severity `json:"severity"`
	Code       string   `json:"code"`
	Message    string   `json:"message"`
	Suggestion string   `json:"suggestion,omitempty"`
	Source     string   `json:"source,omitempty"`
	Line       int      `json:"line,omitempty"`
	ResourceID string   `json:"resource_id,omitempty"`
}

type Summary struct {
	FilesScanned int              `json:"files_scanned"`
	Resources    int              `json:"resources"`
	Ports        int              `json:"ports"`
	References   int              `json:"references"`
	Errors       int              `json:"errors"`
	Warnings     int              `json:"warnings"`
	Platforms    map[Platform]int `json:"platforms"`
}

type Report struct {
	Root        string      `json:"root"`
	GeneratedAt time.Time   `json:"generated_at"`
	Resources   []Resource  `json:"resources"`
	Ports       []Port      `json:"ports"`
	References  []Reference `json:"references"`
	Findings    []Finding   `json:"findings"`
	Summary     Summary     `json:"summary"`
}

func (r Report) HasErrors() bool   { return r.Summary.Errors > 0 }
func (r Report) HasWarnings() bool { return r.Summary.Warnings > 0 }
