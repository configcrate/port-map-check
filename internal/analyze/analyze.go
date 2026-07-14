package analyze

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/configcrate/port-map-check/internal/model"
	"github.com/configcrate/port-map-check/internal/scan"
)

func Build(root string, input scan.Result) model.Report {
	findings := append([]model.Finding(nil), input.Findings...)
	findings = append(findings, analyzeCompose(input)...)
	findings = append(findings, analyzeKubernetes(input)...)
	findings = append(findings, analyzeDockerfiles(input)...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity == model.SeverityError
		}
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		if findings[i].Source != findings[j].Source {
			return findings[i].Source < findings[j].Source
		}
		return findings[i].Line < findings[j].Line
	})
	summary := model.Summary{FilesScanned: input.FilesScanned, Resources: len(input.Resources), Ports: len(input.Ports), References: len(input.References), Platforms: map[model.Platform]int{}}
	for _, resource := range input.Resources {
		summary.Platforms[resource.Platform]++
	}
	for _, finding := range findings {
		if finding.Severity == model.SeverityError {
			summary.Errors++
		} else {
			summary.Warnings++
		}
	}
	return model.Report{Root: root, GeneratedAt: time.Now().UTC(), Resources: input.Resources, Ports: input.Ports, References: input.References, Findings: findings, Summary: summary}
}

func analyzeCompose(input scan.Result) []model.Finding {
	var findings []model.Finding
	bySourceService := map[string]map[string][]model.Port{}
	for _, port := range input.Ports {
		if port.Platform != model.PlatformCompose {
			continue
		}
		if bySourceService[port.Source] == nil {
			bySourceService[port.Source] = map[string][]model.Port{}
		}
		bySourceService[port.Source][strings.ToLower(port.Service)] = append(bySourceService[port.Source][strings.ToLower(port.Service)], port)
	}
	for source, services := range bySourceService {
		seen := map[string][]model.Port{}
		for _, ports := range services {
			for _, port := range ports {
				if port.Kind != model.PortPublished || port.Published == 0 {
					continue
				}
				host := port.HostIP
				if host == "" {
					host = "0.0.0.0"
				}
				key := fmt.Sprintf("%d/%s", port.Published, port.Protocol)
				var previous model.Port
				conflict := false
				for _, candidate := range seen[key] {
					candidateHost := candidate.HostIP
					if candidateHost == "" {
						candidateHost = "0.0.0.0"
					}
					if candidate.Service != port.Service && hostBindingsOverlap(candidateHost, host) {
						previous, conflict = candidate, true
						break
					}
				}
				if conflict {
					severity := model.SeverityError
					if len(previous.Profiles) > 0 || len(port.Profiles) > 0 {
						severity = model.SeverityWarning
					}
					findings = append(findings, model.Finding{Severity: severity, Code: "compose-duplicate-host-port", Source: source, Line: port.Line, ResourceID: port.ResourceID, Message: fmt.Sprintf("Compose services %q and %q have overlapping host bindings on port %s.", previous.Service, port.Service, key), Suggestion: "Assign a different published port or ensure the services can never be active in the same profile set."})
				}
				seen[key] = append(seen[key], port)
			}
		}
	}

	for _, ref := range input.References {
		if ref.Platform != model.PlatformCompose || ref.Port == 0 {
			continue
		}
		services := bySourceService[ref.Source]
		ownerPorts := services[strings.ToLower(ref.Owner)]
		if isLocalhost(ref.Host) {
			if ref.Context == "healthcheck" {
				for _, port := range ownerPorts {
					if port.Kind == model.PortPublished && port.Published == ref.Port && port.Target != ref.Port {
						findings = append(findings, model.Finding{Severity: model.SeverityError, Code: "compose-healthcheck-host-port", Source: ref.Source, Line: ref.Line, ResourceID: ref.ResourceID, Message: fmt.Sprintf("Healthcheck for %q uses published port %d from inside the container, but the container port is %d.", ref.Owner, ref.Port, port.Target), Suggestion: fmt.Sprintf("Change the healthcheck URL to localhost:%d.", port.Target)})
						break
					}
				}
			}
			for service, ports := range services {
				if service == strings.ToLower(ref.Owner) {
					continue
				}
				if hasTarget(ports, ref.Port, "") {
					findings = append(findings, model.Finding{Severity: model.SeverityWarning, Code: "compose-localhost-cross-service", Source: ref.Source, Line: ref.Line, ResourceID: ref.ResourceID, Message: fmt.Sprintf("%q references localhost:%d, which matches the container port of Compose service %q. Inside a container, localhost refers to the current container.", ref.Owner, ref.Port, service), Suggestion: fmt.Sprintf("Use %s:%d if the connection is intended for that Compose service.", service, ref.Port)})
					break
				}
			}
			continue
		}
		targetPorts, exists := services[strings.ToLower(ref.Host)]
		if !exists {
			continue
		}
		if hasTarget(targetPorts, ref.Port, "") {
			continue
		}
		if target, ok := targetForPublished(targetPorts, ref.Port); ok && target != ref.Port {
			findings = append(findings, model.Finding{Severity: model.SeverityError, Code: "compose-service-uses-host-port", Source: ref.Source, Line: ref.Line, ResourceID: ref.ResourceID, Message: fmt.Sprintf("%q connects to Compose service %q on published host port %d; service-to-service traffic must use container port %d.", ref.Owner, ref.Host, ref.Port, target), Suggestion: fmt.Sprintf("Change the URL to %s:%d.", ref.Host, target)})
		} else if len(targetPorts) > 0 {
			findings = append(findings, model.Finding{Severity: model.SeverityWarning, Code: "compose-service-port-mismatch", Source: ref.Source, Line: ref.Line, ResourceID: ref.ResourceID, Message: fmt.Sprintf("%q connects to Compose service %q on port %d, but that service declares different container ports.", ref.Owner, ref.Host, ref.Port), Suggestion: "Verify the service URL against the target side of its Compose port mapping."})
		}
	}
	return deduplicate(findings)
}

func analyzeKubernetes(input scan.Result) []model.Finding {
	var findings []model.Finding
	resources := map[string]model.Resource{}
	services := map[string]model.Resource{}
	portsByResource := map[string][]model.Port{}
	for _, resource := range input.Resources {
		resources[resource.ID] = resource
		if resource.Platform == model.PlatformKubernetes && strings.EqualFold(resource.Kind, "Service") {
			services[kubeKey(resource.Namespace, resource.Name)] = resource
		}
	}
	for _, port := range input.Ports {
		portsByResource[port.ResourceID] = append(portsByResource[port.ResourceID], port)
	}
	seenNodePort := map[string]model.Port{}
	for _, port := range input.Ports {
		if port.Platform != model.PlatformKubernetes || port.Kind != model.PortNode {
			continue
		}
		key := fmt.Sprintf("%d/%s", port.Published, port.Protocol)
		if previous, ok := seenNodePort[key]; ok && previous.ResourceID != port.ResourceID {
			findings = append(findings, model.Finding{Severity: model.SeverityError, Code: "k8s-duplicate-node-port", Source: port.Source, Line: port.Line, ResourceID: port.ResourceID, Message: fmt.Sprintf("Kubernetes Services %q and %q both reserve NodePort %s.", previous.Service, port.Service, key), Suggestion: "Assign a unique nodePort or let Kubernetes allocate one."})
		} else {
			seenNodePort[key] = port
		}
	}

	for _, service := range services {
		matched := matchingWorkloads(service, input.Resources)
		if len(service.Selector) > 0 && len(matched) == 0 {
			findings = append(findings, model.Finding{Severity: model.SeverityWarning, Code: "k8s-service-no-workload", Source: service.Source, Line: service.Line, ResourceID: service.ID, Message: fmt.Sprintf("Kubernetes Service %q has a selector that matches no scanned workload.", service.Name), Suggestion: "Align the Service selector with pod-template labels or include the missing manifest in the scan."})
			continue
		}
		var workloadPorts []model.Port
		for _, workload := range matched {
			workloadPorts = append(workloadPorts, portsByResource[workload.ID]...)
		}
		if len(workloadPorts) == 0 {
			continue
		}
		for _, port := range portsByResource[service.ID] {
			if port.Kind != model.PortService {
				continue
			}
			if port.TargetName != "" && !hasTarget(workloadPorts, 0, port.TargetName) {
				findings = append(findings, model.Finding{Severity: model.SeverityError, Code: "k8s-target-name-mismatch", Source: port.Source, Line: port.Line, ResourceID: service.ID, Message: fmt.Sprintf("Service %q targets named port %q, but no selected workload declares that port name.", service.Name, port.TargetName), Suggestion: "Use a container port name declared by the selected workload."})
			} else if port.Target != 0 && !hasTarget(workloadPorts, port.Target, "") {
				findings = append(findings, model.Finding{Severity: model.SeverityWarning, Code: "k8s-target-port-mismatch", Source: port.Source, Line: port.Line, ResourceID: service.ID, Message: fmt.Sprintf("Service %q targets port %d, but selected workloads declare different container ports.", service.Name, port.Target), Suggestion: "Align targetPort with a declared containerPort, or omit containerPort declarations if they are intentionally documentary."})
			}
		}
	}

	for _, ref := range input.References {
		if ref.Platform != model.PlatformKubernetes {
			continue
		}
		if strings.HasSuffix(ref.Context, "Probe") || strings.HasSuffix(strings.ToLower(ref.Context), "probe") {
			declared := portsByResource[ref.ResourceID]
			if len(declared) > 0 && !hasTarget(declared, ref.Port, ref.PortName) {
				severity := model.SeverityWarning
				if ref.PortName != "" {
					severity = model.SeverityError
				}
				findings = append(findings, model.Finding{Severity: severity, Code: "k8s-probe-port-mismatch", Source: ref.Source, Line: ref.Line, ResourceID: ref.ResourceID, Message: fmt.Sprintf("%s for %q uses port %s, but the workload declares different container ports.", ref.Context, ref.Owner, referencePort(ref)), Suggestion: "Point the probe at a declared container port name or number, or confirm that the undeclared numeric port is intentional."})
			}
			continue
		}
		serviceNamespace, serviceName := kubeServiceHost(ref.Namespace, ref.Host)
		service, exists := services[kubeKey(serviceNamespace, serviceName)]
		if ref.Context == "ingress-backend" && !exists {
			findings = append(findings, model.Finding{Severity: model.SeverityError, Code: "k8s-ingress-service-missing", Source: ref.Source, Line: ref.Line, ResourceID: ref.ResourceID, Message: fmt.Sprintf("Ingress %q references missing Service %q in namespace %q.", ref.Owner, serviceName, serviceNamespace), Suggestion: "Create the Service or correct the Ingress backend name."})
			continue
		}
		if !exists {
			continue
		}
		servicePorts := portsByResource[service.ID]
		if !hasServicePort(servicePorts, ref.Port, ref.PortName) {
			severity := model.SeverityWarning
			code := "k8s-service-port-reference-mismatch"
			if ref.Context == "ingress-backend" {
				severity = model.SeverityError
				code = "k8s-ingress-port-mismatch"
			}
			findings = append(findings, model.Finding{Severity: severity, Code: code, Source: ref.Source, Line: ref.Line, ResourceID: ref.ResourceID, Message: fmt.Sprintf("%s from %q references Service %q port %s, but the Service exposes different ports.", ref.Context, ref.Owner, serviceName, referencePort(ref)), Suggestion: "Use a Service port name or number from the Service spec."})
		}
	}
	return deduplicate(findings)
}

func analyzeDockerfiles(input scan.Result) []model.Finding {
	var findings []model.Finding
	portsBySource := map[string][]model.Port{}
	for _, port := range input.Ports {
		portsBySource[filepath.ToSlash(filepath.Clean(port.Source))] = append(portsBySource[filepath.ToSlash(filepath.Clean(port.Source))], port)
	}
	for _, resource := range input.Resources {
		if resource.Platform != model.PlatformCompose {
			continue
		}
		context := resource.Metadata["build_context"]
		if context == "" || strings.Contains(context, "${") || strings.HasPrefix(context, "http") {
			continue
		}
		dockerfile := resource.Metadata["dockerfile"]
		if dockerfile == "" {
			dockerfile = "Dockerfile"
		}
		composeDir := filepath.Dir(filepath.FromSlash(resource.Source))
		dockerfilePath := filepath.ToSlash(filepath.Clean(filepath.Join(composeDir, filepath.FromSlash(context), filepath.FromSlash(dockerfile))))
		exposed := portsBySource[dockerfilePath]
		if len(exposed) == 0 {
			continue
		}
		var composePorts []model.Port
		for _, port := range input.Ports {
			if port.ResourceID == resource.ID && (port.Kind == model.PortPublished || port.Kind == model.PortContainer) {
				composePorts = append(composePorts, port)
			}
		}
		if len(composePorts) == 0 || intersectsTargets(composePorts, exposed) {
			continue
		}
		findings = append(findings, model.Finding{Severity: model.SeverityWarning, Code: "dockerfile-expose-mismatch", Source: resource.Source, Line: resource.Line, ResourceID: resource.ID, Message: fmt.Sprintf("Compose service %q maps container ports that do not match EXPOSE instructions in %s.", resource.Name, dockerfilePath), Suggestion: "Confirm the application listen port, then align Compose target ports and Dockerfile EXPOSE documentation."})
	}
	return findings
}

func matchingWorkloads(service model.Resource, resources []model.Resource) []model.Resource {
	var result []model.Resource
	for _, resource := range resources {
		if resource.Platform != model.PlatformKubernetes || resource.Namespace != service.Namespace || strings.EqualFold(resource.Kind, "Service") || strings.EqualFold(resource.Kind, "Ingress") {
			continue
		}
		if selectorMatches(service.Selector, resource.Labels) {
			result = append(result, resource)
		}
	}
	return result
}

func selectorMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func hasTarget(ports []model.Port, number int, name string) bool {
	for _, port := range ports {
		if name != "" && strings.EqualFold(port.Name, name) {
			return true
		}
		if number != 0 && port.Target == number {
			return true
		}
	}
	return false
}

func hasServicePort(ports []model.Port, number int, name string) bool {
	for _, port := range ports {
		if port.Kind != model.PortService {
			continue
		}
		if name != "" && strings.EqualFold(port.Name, name) {
			return true
		}
		if number != 0 && port.Published == number {
			return true
		}
	}
	return false
}

func targetForPublished(ports []model.Port, published int) (int, bool) {
	for _, port := range ports {
		if port.Kind == model.PortPublished && port.Published == published {
			return port.Target, true
		}
	}
	return 0, false
}

func intersectsTargets(left, right []model.Port) bool {
	for _, a := range left {
		for _, b := range right {
			if a.Target != 0 && a.Target == b.Target && a.Protocol == b.Protocol {
				return true
			}
		}
	}
	return false
}

func isLocalhost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0"
}

func hostBindingsOverlap(left, right string) bool {
	left = strings.Trim(strings.ToLower(left), "[]")
	right = strings.Trim(strings.ToLower(right), "[]")
	if left == "" {
		left = "0.0.0.0"
	}
	if right == "" {
		right = "0.0.0.0"
	}
	if left == right {
		return true
	}
	leftV6, rightV6 := strings.Contains(left, ":"), strings.Contains(right, ":")
	if leftV6 != rightV6 {
		return false
	}
	if leftV6 {
		return left == "::" || right == "::"
	}
	return left == "0.0.0.0" || right == "0.0.0.0"
}

func kubeKey(namespace, name string) string { return strings.ToLower(namespace + "/" + name) }

func kubeServiceHost(defaultNamespace, host string) (namespace, name string) {
	parts := strings.Split(strings.ToLower(host), ".")
	name, namespace = parts[0], defaultNamespace
	if len(parts) >= 3 && parts[2] == "svc" {
		namespace = parts[1]
	}
	return namespace, name
}

func referencePort(ref model.Reference) string {
	if ref.PortName != "" {
		return fmt.Sprintf("%q", ref.PortName)
	}
	return fmt.Sprintf("%d", ref.Port)
}

func deduplicate(findings []model.Finding) []model.Finding {
	seen := map[string]bool{}
	result := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		key := fmt.Sprintf("%s|%s|%s|%d|%s", finding.Severity, finding.Code, finding.Source, finding.Line, finding.Message)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, finding)
	}
	return result
}
