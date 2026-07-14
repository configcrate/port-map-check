package scan

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/configcrate/port-map-check/internal/model"
	"gopkg.in/yaml.v3"
)

func parseCompose(source string, data []byte, result *Result) error {
	var document yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&document); err != nil {
		return err
	}
	if len(document.Content) == 0 {
		return nil
	}
	root := document.Content[0]
	services := mapNode(root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(services.Content); index += 2 {
		nameNode, serviceNode := services.Content[index], services.Content[index+1]
		name := nameNode.Value
		id := resourceID(model.PlatformCompose, "", name, source)
		metadata := map[string]string{}
		if build := mapNode(serviceNode, "build"); build != nil {
			if build.Kind == yaml.ScalarNode {
				metadata["build_context"] = build.Value
			} else if build.Kind == yaml.MappingNode {
				metadata["build_context"] = scalarValue(build, "context")
				metadata["dockerfile"] = scalarValue(build, "dockerfile")
			}
		}
		resource := model.Resource{ID: id, Platform: model.PlatformCompose, Kind: "Compose service", Name: name, Source: source, Line: nameNode.Line, Metadata: metadata}
		result.Resources = append(result.Resources, resource)
		profiles := nodeStrings(mapNode(serviceNode, "profiles"))
		parseComposePorts(source, name, id, profiles, mapNode(serviceNode, "ports"), result)
		parseComposeExpose(source, name, id, profiles, mapNode(serviceNode, "expose"), result)
		parseComposeEnvironment(source, name, id, mapNode(serviceNode, "environment"), result)
		parseComposeHealthcheck(source, name, id, mapNode(serviceNode, "healthcheck"), result)
	}
	return nil
}

func parseComposePorts(source, service, id string, profiles []string, node *yaml.Node, result *Result) {
	if node == nil || node.Kind != yaml.SequenceNode {
		return
	}
	for index, item := range node.Content {
		var hostIP, protocol, name string
		published, target := 0, 0
		protocol = "tcp"
		switch item.Kind {
		case yaml.ScalarNode:
			hostIP, published, target, protocol = parseComposeShortPort(item.Value)
		case yaml.MappingNode:
			hostIP = scalarValue(item, "host_ip")
			published = nodeInt(mapNode(item, "published"))
			target = nodeInt(mapNode(item, "target"))
			protocol = strings.ToLower(scalarValue(item, "protocol"))
			name = scalarValue(item, "name")
			if protocol == "" {
				protocol = "tcp"
			}
		}
		if target < 1 || target > 65535 || published < 0 || published > 65535 {
			result.Findings = append(result.Findings, model.Finding{Severity: model.SeverityWarning, Code: "compose-port-unresolved", Source: source, Line: item.Line, ResourceID: id, Message: fmt.Sprintf("Could not resolve port mapping %q for Compose service %q.", item.Value, service), Suggestion: "Use a concrete numeric port or scan the fully interpolated Compose configuration."})
			continue
		}
		result.Ports = append(result.Ports, model.Port{ID: portID(id, model.PortPublished, published, target, name, index), Platform: model.PlatformCompose, Kind: model.PortPublished, ResourceID: id, Service: service, Source: source, Line: item.Line, HostIP: hostIP, Published: published, Target: target, Name: name, Protocol: protocol, Profiles: profiles})
	}
}

func parseComposeShortPort(value string) (hostIP string, published, target int, protocol string) {
	protocol = "tcp"
	value = strings.Trim(strings.TrimSpace(value), "\"")
	if slash := strings.LastIndex(value, "/"); slash >= 0 {
		protocol = strings.ToLower(value[slash+1:])
		value = value[:slash]
	}
	if strings.Contains(value, "-") || strings.Contains(value, "${") {
		return "", 0, 0, protocol
	}
	parts := strings.Split(value, ":")
	if len(parts) == 1 {
		target, _ = strconv.Atoi(parts[0])
		return
	}
	target, _ = strconv.Atoi(parts[len(parts)-1])
	published, _ = strconv.Atoi(parts[len(parts)-2])
	if len(parts) > 2 {
		hostIP = strings.Trim(strings.Join(parts[:len(parts)-2], ":"), "[]")
	}
	return
}

func parseComposeExpose(source, service, id string, profiles []string, node *yaml.Node, result *Result) {
	if node == nil || node.Kind != yaml.SequenceNode {
		return
	}
	for index, item := range node.Content {
		value := strings.TrimSpace(item.Value)
		protocol := "tcp"
		if slash := strings.LastIndex(value, "/"); slash >= 0 {
			protocol = strings.ToLower(value[slash+1:])
			value = value[:slash]
		}
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		result.Ports = append(result.Ports, model.Port{ID: portID(id, model.PortContainer, 0, port, "", index), Platform: model.PlatformCompose, Kind: model.PortContainer, ResourceID: id, Service: service, Source: source, Line: item.Line, Target: port, Protocol: protocol, Profiles: profiles})
	}
}

func parseComposeEnvironment(source, service, id string, node *yaml.Node, result *Result) {
	if node == nil {
		return
	}
	values := []struct {
		value string
		line  int
	}{}
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			values = append(values, struct {
				value string
				line  int
			}{node.Content[index+1].Value, node.Content[index+1].Line})
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			value := item.Value
			if equal := strings.Index(value, "="); equal >= 0 {
				value = value[equal+1:]
			}
			values = append(values, struct {
				value string
				line  int
			}{value, item.Line})
		}
	}
	for _, value := range values {
		base := model.Reference{Platform: model.PlatformCompose, ResourceID: id, Owner: service, Context: "environment", Source: source, Line: value.line}
		result.References = append(result.References, parseURLReferences(value.value, base)...)
	}
}

func parseComposeHealthcheck(source, service, id string, node *yaml.Node, result *Result) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	test := mapNode(node, "test")
	if test == nil {
		return
	}
	var parts []string
	if test.Kind == yaml.SequenceNode {
		parts = nodeStrings(test)
	} else {
		parts = []string{test.Value}
	}
	base := model.Reference{Platform: model.PlatformCompose, ResourceID: id, Owner: service, Context: "healthcheck", Source: source, Line: test.Line}
	result.References = append(result.References, parseURLReferences(strings.Join(parts, " "), base)...)
}

func nodeStrings(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		return []string{node.Value}
	}
	var values []string
	for _, item := range node.Content {
		values = append(values, item.Value)
	}
	return values
}

func nodeInt(node *yaml.Node) int {
	if node == nil {
		return 0
	}
	value, _ := strconv.Atoi(node.Value)
	return value
}
