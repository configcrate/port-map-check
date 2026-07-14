package scan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/configcrate/port-map-check/internal/model"
	"gopkg.in/yaml.v3"
)

func parseKubernetesDocument(source string, root *yaml.Node, result *Result) {
	kind := scalarValue(root, "kind")
	if strings.EqualFold(kind, "List") {
		items := mapNode(root, "items")
		if items != nil && items.Kind == yaml.SequenceNode {
			for _, item := range items.Content {
				parseKubernetesDocument(source, item, result)
			}
		}
		return
	}
	metadata := mapNode(root, "metadata")
	name := scalarValue(metadata, "name")
	if name == "" {
		return
	}
	namespace := scalarValue(metadata, "namespace")
	if namespace == "" {
		namespace = "default"
	}
	id := resourceID(model.PlatformKubernetes, namespace, name, source)
	resource := model.Resource{ID: id, Platform: model.PlatformKubernetes, Kind: kind, Name: name, Namespace: namespace, Source: source, Line: root.Line, Labels: nodeStringMap(mapNode(metadata, "labels"))}

	switch strings.ToLower(kind) {
	case "service":
		resource.Selector = nodeStringMap(pathNode(root, "spec", "selector"))
		result.Resources = append(result.Resources, resource)
		parseKubeServicePorts(source, id, name, namespace, pathNode(root, "spec", "ports"), result)
	case "ingress":
		result.Resources = append(result.Resources, resource)
		parseIngress(source, id, name, namespace, root, result)
	case "pod", "deployment", "statefulset", "daemonset", "replicaset", "job", "cronjob":
		podMetadata, podSpec := kubePodTemplate(root, strings.ToLower(kind))
		if podMetadata != nil {
			resource.Labels = nodeStringMap(mapNode(podMetadata, "labels"))
		}
		result.Resources = append(result.Resources, resource)
		parsePodSpec(source, id, name, namespace, podSpec, result)
	default:
		return
	}
}

func kubePodTemplate(root *yaml.Node, kind string) (metadata, spec *yaml.Node) {
	switch kind {
	case "pod":
		return mapNode(root, "metadata"), mapNode(root, "spec")
	case "cronjob":
		template := pathNode(root, "spec", "jobTemplate", "spec", "template")
		return mapNode(template, "metadata"), mapNode(template, "spec")
	default:
		template := pathNode(root, "spec", "template")
		return mapNode(template, "metadata"), mapNode(template, "spec")
	}
}

func parseKubeServicePorts(source, id, service, namespace string, node *yaml.Node, result *Result) {
	if node == nil || node.Kind != yaml.SequenceNode {
		return
	}
	for index, item := range node.Content {
		name := scalarValue(item, "name")
		protocol := strings.ToLower(scalarValue(item, "protocol"))
		if protocol == "" {
			protocol = "tcp"
		}
		servicePort := nodeInt(mapNode(item, "port"))
		targetNode := mapNode(item, "targetPort")
		target, targetName := 0, ""
		if targetNode == nil {
			target = servicePort
		} else if targetNode.Tag == "!!int" {
			target = nodeInt(targetNode)
		} else if parsed, err := strconv.Atoi(targetNode.Value); err == nil {
			target = parsed
		} else {
			targetName = targetNode.Value
		}
		result.Ports = append(result.Ports, model.Port{ID: portID(id, model.PortService, servicePort, target, name, index), Platform: model.PlatformKubernetes, Kind: model.PortService, ResourceID: id, Service: service, Namespace: namespace, Source: source, Line: item.Line, Published: servicePort, Target: target, TargetName: targetName, Name: name, Protocol: protocol})
		if nodePort := nodeInt(mapNode(item, "nodePort")); nodePort != 0 {
			result.Ports = append(result.Ports, model.Port{ID: portID(id, model.PortNode, nodePort, target, name, index), Platform: model.PlatformKubernetes, Kind: model.PortNode, ResourceID: id, Service: service, Namespace: namespace, Source: source, Line: item.Line, Published: nodePort, Target: target, TargetName: targetName, Name: name, Protocol: protocol})
		}
	}
}

func parsePodSpec(source, id, owner, namespace string, spec *yaml.Node, result *Result) {
	if spec == nil {
		return
	}
	for _, key := range []string{"initContainers", "containers"} {
		containers := mapNode(spec, key)
		if containers == nil || containers.Kind != yaml.SequenceNode {
			continue
		}
		for containerIndex, container := range containers.Content {
			containerName := scalarValue(container, "name")
			if containerName == "" {
				containerName = fmt.Sprintf("container-%d", containerIndex+1)
			}
			ports := mapNode(container, "ports")
			if ports != nil && ports.Kind == yaml.SequenceNode {
				for portIndex, item := range ports.Content {
					port := nodeInt(mapNode(item, "containerPort"))
					if port == 0 {
						continue
					}
					name := scalarValue(item, "name")
					protocol := strings.ToLower(scalarValue(item, "protocol"))
					if protocol == "" {
						protocol = "tcp"
					}
					metadata := map[string]string{"container": containerName}
					result.Ports = append(result.Ports, model.Port{ID: portID(id, model.PortContainer, 0, port, name, containerIndex*1000+portIndex), Platform: model.PlatformKubernetes, Kind: model.PortContainer, ResourceID: id, Service: owner, Namespace: namespace, Source: source, Line: item.Line, Target: port, Name: name, Protocol: protocol, Metadata: metadata})
				}
			}
			parseKubeEnv(source, id, owner, namespace, container, result)
			parseKubeCommands(source, id, owner, namespace, container, result)
			for _, probeName := range []string{"livenessProbe", "readinessProbe", "startupProbe"} {
				parseKubeProbe(source, id, owner, namespace, probeName, mapNode(container, probeName), result)
			}
		}
	}
}

func parseKubeEnv(source, id, owner, namespace string, container *yaml.Node, result *Result) {
	env := mapNode(container, "env")
	if env == nil || env.Kind != yaml.SequenceNode {
		return
	}
	for _, item := range env.Content {
		value := mapNode(item, "value")
		if value == nil {
			continue
		}
		base := model.Reference{Platform: model.PlatformKubernetes, ResourceID: id, Owner: owner, Namespace: namespace, Context: "environment", Source: source, Line: value.Line}
		result.References = append(result.References, parseURLReferences(value.Value, base)...)
	}
}

func parseKubeCommands(source, id, owner, namespace string, container *yaml.Node, result *Result) {
	for _, key := range []string{"command", "args"} {
		node := mapNode(container, key)
		if node == nil {
			continue
		}
		base := model.Reference{Platform: model.PlatformKubernetes, ResourceID: id, Owner: owner, Namespace: namespace, Context: key, Source: source, Line: node.Line}
		result.References = append(result.References, parseURLReferences(strings.Join(nodeStrings(node), " "), base)...)
	}
}

func parseKubeProbe(source, id, owner, namespace, probeName string, probe *yaml.Node, result *Result) {
	httpGet := mapNode(probe, "httpGet")
	if httpGet == nil {
		return
	}
	portNode := mapNode(httpGet, "port")
	if portNode == nil {
		return
	}
	ref := model.Reference{Platform: model.PlatformKubernetes, ResourceID: id, Owner: owner, Namespace: namespace, Host: "localhost", Context: probeName, Source: source, Line: portNode.Line, Scheme: strings.ToLower(scalarValue(httpGet, "scheme"))}
	if ref.Scheme == "" {
		ref.Scheme = "http"
	}
	if portNode.Tag == "!!int" {
		ref.Port = nodeInt(portNode)
	} else if parsed, err := strconv.Atoi(portNode.Value); err == nil {
		ref.Port = parsed
	} else {
		ref.PortName = portNode.Value
	}
	result.References = append(result.References, ref)
}

func parseIngress(source, id, owner, namespace string, root *yaml.Node, result *Result) {
	rules := pathNode(root, "spec", "rules")
	if rules != nil && rules.Kind == yaml.SequenceNode {
		for _, rule := range rules.Content {
			paths := pathNode(rule, "http", "paths")
			if paths == nil || paths.Kind != yaml.SequenceNode {
				continue
			}
			for _, path := range paths.Content {
				parseIngressBackend(source, id, owner, namespace, mapNode(path, "backend"), result)
			}
		}
	}
	parseIngressBackend(source, id, owner, namespace, pathNode(root, "spec", "defaultBackend"), result)
}

func parseIngressBackend(source, id, owner, namespace string, backend *yaml.Node, result *Result) {
	if backend == nil {
		return
	}
	service := mapNode(backend, "service")
	ref := model.Reference{Platform: model.PlatformKubernetes, ResourceID: id, Owner: owner, Namespace: namespace, Context: "ingress-backend", Source: source, Line: backend.Line}
	if service != nil {
		ref.Host = strings.ToLower(scalarValue(service, "name"))
		port := mapNode(service, "port")
		if number := mapNode(port, "number"); number != nil {
			ref.Port = nodeInt(number)
		} else {
			ref.PortName = scalarValue(port, "name")
		}
	} else {
		ref.Host = strings.ToLower(scalarValue(backend, "serviceName"))
		legacyPort := mapNode(backend, "servicePort")
		if legacyPort != nil {
			if parsed, err := strconv.Atoi(legacyPort.Value); err == nil {
				ref.Port = parsed
			} else {
				ref.PortName = legacyPort.Value
			}
		}
	}
	if ref.Host == "" || (ref.Port == 0 && ref.PortName == "") {
		return
	}
	result.References = append(result.References, ref)
}

func pathNode(root *yaml.Node, keys ...string) *yaml.Node {
	current := root
	for _, key := range keys {
		current = mapNode(current, key)
		if current == nil {
			return nil
		}
	}
	return current
}
