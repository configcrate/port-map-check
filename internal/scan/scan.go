package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/configcrate/port-map-check/internal/model"
	"gopkg.in/yaml.v3"
)

type Options struct {
	MaxFileSize int64
	Exclude     []string
}

type Result struct {
	Resources    []model.Resource
	Ports        []model.Port
	References   []model.Reference
	Findings     []model.Finding
	FilesScanned int
}

var urlPattern = regexp.MustCompile(`(?i)\b(?:https?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mongodb(?:\+srv)?|grpc)://[^\s"'<>]+`)

func Repository(root string, options Options) (Result, error) {
	if options.MaxFileSize == 0 {
		options.MaxFileSize = 2 << 20
	}
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, err
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("%s is not a directory", root)
	}
	excludes, err := compileExcludes(options.Exclude)
	if err != nil {
		return Result{}, err
	}
	var result Result
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && matchesExclude(rel, excludes) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if path != root && shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !candidate(path) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > options.MaxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result.FilesScanned++
		base := strings.ToLower(filepath.Base(path))
		switch {
		case isDockerfile(base):
			parseDockerfile(rel, data, &result)
		case base == "devcontainer.json":
			parseDevContainer(rel, data, &result)
		case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
			if isComposeName(base) {
				if err := parseCompose(rel, data, &result); err != nil {
					addParseFinding(rel, err, &result)
				}
			} else if looksLikeHelmTemplate(rel, data) {
				return nil
			} else if err := parseYAMLDocuments(rel, data, &result); err != nil {
				addParseFinding(rel, err, &result)
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].ID < result.Resources[j].ID })
	sort.Slice(result.Ports, func(i, j int) bool { return result.Ports[i].ID < result.Ports[j].ID })
	return result, nil
}

func compileExcludes(patterns []string) ([]*regexp.Regexp, error) {
	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(filepath.ToSlash(pattern))
		pattern = strings.TrimPrefix(pattern, "./")
		pattern = strings.TrimPrefix(pattern, "/")
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "/") {
			pattern += "**"
		}
		var expression strings.Builder
		expression.WriteString("^")
		for index := 0; index < len(pattern); index++ {
			switch pattern[index] {
			case '*':
				if index+1 < len(pattern) && pattern[index+1] == '*' {
					expression.WriteString(".*")
					index++
				} else {
					expression.WriteString("[^/]*")
				}
			case '?':
				expression.WriteString("[^/]")
			default:
				expression.WriteString(regexp.QuoteMeta(string(pattern[index])))
			}
		}
		expression.WriteString("$")
		value, err := regexp.Compile(expression.String())
		if err != nil {
			return nil, fmt.Errorf("invalid exclude pattern %q: %w", pattern, err)
		}
		compiled = append(compiled, value)
	}
	return compiled, nil
}

func matchesExclude(path string, patterns []*regexp.Regexp) bool {
	path = filepath.ToSlash(path)
	for _, pattern := range patterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

func looksLikeHelmTemplate(source string, data []byte) bool {
	normalized := "/" + strings.ToLower(filepath.ToSlash(source))
	return strings.Contains(normalized, "/templates/") && bytes.Contains(data, []byte("{{"))
}

func shouldSkipDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".venv", "venv", "target":
		return true
	default:
		return false
	}
}

func candidate(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return isDockerfile(base) || base == "devcontainer.json" || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}

func isDockerfile(base string) bool {
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.")
}

func isComposeName(base string) bool {
	return base == "compose.yaml" || base == "compose.yml" || strings.HasPrefix(base, "compose.") ||
		base == "docker-compose.yaml" || base == "docker-compose.yml" || strings.HasPrefix(base, "docker-compose.")
}

func addParseFinding(source string, err error, result *Result) {
	result.Findings = append(result.Findings, model.Finding{
		Severity: model.SeverityWarning, Code: "parse-error", Source: source,
		Message:    fmt.Sprintf("Could not parse a candidate configuration file: %v", err),
		Suggestion: "Fix the syntax or exclude generated configuration directories from the scan.",
	})
}

func resourceID(platform model.Platform, namespace, name, source string) string {
	if namespace == "" {
		namespace = "default"
	}
	return fmt.Sprintf("%s:%s:%s@%s", platform, namespace, name, source)
}

func portID(resourceID string, kind model.PortKind, published, target int, name string, index int) string {
	return fmt.Sprintf("%s:%s:%d:%d:%s:%d", resourceID, kind, published, target, name, index)
}

func parseURLReferences(value string, base model.Reference) []model.Reference {
	var references []model.Reference
	for _, match := range urlPattern.FindAllString(value, -1) {
		trimmed := strings.TrimRight(match, ").,;]")
		parsed, err := url.Parse(trimmed)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		ref := base
		ref.Host = strings.ToLower(parsed.Hostname())
		ref.Scheme = strings.ToLower(parsed.Scheme)
		if rawPort := parsed.Port(); rawPort != "" {
			ref.Port, _ = strconv.Atoi(rawPort)
		} else {
			ref.Port = defaultPort(ref.Scheme)
		}
		references = append(references, ref)
	}
	return references
}

func defaultPort(scheme string) int {
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	case "postgres", "postgresql":
		return 5432
	case "mysql", "mariadb":
		return 3306
	case "redis", "rediss":
		return 6379
	case "amqp", "amqps":
		return 5672
	case "mongodb":
		return 27017
	case "grpc":
		return 50051
	default:
		return 0
	}
}

func parseDockerfile(source string, data []byte, result *Result) {
	name := filepath.Base(filepath.Dir(source))
	if name == "." || name == "" {
		name = "root"
	}
	id := resourceID(model.PlatformDockerfile, "", name, source)
	resource := model.Resource{ID: id, Platform: model.PlatformDockerfile, Kind: "Dockerfile", Name: name, Source: source}
	result.Resources = append(result.Resources, resource)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	index := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if len(text) < 7 || !strings.EqualFold(text[:6], "EXPOSE") || (len(text) > 6 && text[6] != ' ' && text[6] != '\t') {
			continue
		}
		for _, token := range strings.Fields(text[6:]) {
			protocol := "tcp"
			parts := strings.SplitN(token, "/", 2)
			if len(parts) == 2 {
				protocol = strings.ToLower(parts[1])
			}
			port, err := strconv.Atoi(parts[0])
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			index++
			result.Ports = append(result.Ports, model.Port{ID: portID(id, model.PortExpose, 0, port, "", index), Platform: model.PlatformDockerfile, Kind: model.PortExpose, ResourceID: id, Service: name, Source: source, Line: line, Target: port, Protocol: protocol})
		}
	}
}

func parseDevContainer(source string, data []byte, result *Result) {
	cleaned := stripTrailingJSONCommas(stripJSONComments(data))
	var value struct {
		Name         string `json:"name"`
		ForwardPorts []any  `json:"forwardPorts"`
	}
	if err := json.Unmarshal(cleaned, &value); err != nil {
		addParseFinding(source, err, result)
		return
	}
	name := value.Name
	if name == "" {
		name = filepath.Base(filepath.Dir(source))
	}
	id := resourceID(model.PlatformDevContainer, "", name, source)
	result.Resources = append(result.Resources, model.Resource{ID: id, Platform: model.PlatformDevContainer, Kind: "Dev Container", Name: name, Source: source})
	for index, raw := range value.ForwardPorts {
		port := 0
		switch typed := raw.(type) {
		case float64:
			port = int(typed)
		case string:
			last := typed
			if slash := strings.LastIndex(last, ":"); slash >= 0 {
				last = last[slash+1:]
			}
			port, _ = strconv.Atoi(last)
		}
		if port > 0 && port <= 65535 {
			result.Ports = append(result.Ports, model.Port{ID: portID(id, model.PortForward, port, port, "", index), Platform: model.PlatformDevContainer, Kind: model.PortForward, ResourceID: id, Service: name, Source: source, Published: port, Target: port, Protocol: "tcp"})
		}
	}
}

func stripTrailingJSONCommas(data []byte) []byte {
	var output bytes.Buffer
	inString, escaped := false, false
	for index := 0; index < len(data); index++ {
		current := data[index]
		if !inString && current == ',' {
			lookahead := index + 1
			for lookahead < len(data) && (data[lookahead] == ' ' || data[lookahead] == '\t' || data[lookahead] == '\r' || data[lookahead] == '\n') {
				lookahead++
			}
			if lookahead < len(data) && (data[lookahead] == '}' || data[lookahead] == ']') {
				continue
			}
		}
		output.WriteByte(current)
		if inString {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
		} else if current == '"' {
			inString = true
		}
	}
	return output.Bytes()
}

func stripJSONComments(data []byte) []byte {
	var output bytes.Buffer
	inString, escaped, lineComment, blockComment := false, false, false, false
	for index := 0; index < len(data); index++ {
		current := data[index]
		next := byte(0)
		if index+1 < len(data) {
			next = data[index+1]
		}
		if lineComment {
			if current == '\n' {
				lineComment = false
				output.WriteByte(current)
			}
			continue
		}
		if blockComment {
			if current == '*' && next == '/' {
				blockComment = false
				index++
			} else if current == '\n' {
				output.WriteByte('\n')
			}
			continue
		}
		if !inString && current == '/' && next == '/' {
			lineComment = true
			index++
			continue
		}
		if !inString && current == '/' && next == '*' {
			blockComment = true
			index++
			continue
		}
		output.WriteByte(current)
		if inString {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
		} else if current == '"' {
			inString = true
		}
	}
	return output.Bytes()
}

func parseYAMLDocuments(source string, data []byte, result *Result) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(document.Content) == 0 {
			continue
		}
		root := document.Content[0]
		kind := scalarValue(root, "kind")
		if kind == "" {
			continue
		}
		parseKubernetesDocument(source, root, result)
	}
}

func scalarValue(mapping *yaml.Node, key string) string {
	value := mapNode(mapping, key)
	if value == nil {
		return ""
	}
	return value.Value
}

func mapNode(mapping *yaml.Node, key string) *yaml.Node {
	return mapNodeDepth(mapping, key, 0)
}

func mapNodeDepth(mapping *yaml.Node, key string, depth int) *yaml.Node {
	if depth > 32 {
		return nil
	}
	if mapping != nil && mapping.Kind == yaml.AliasNode {
		return mapNodeDepth(mapping.Alias, key, depth+1)
	}
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value != "<<" {
			continue
		}
		merged := mapping.Content[index+1]
		if merged.Kind == yaml.SequenceNode {
			for _, item := range merged.Content {
				if value := mapNodeDepth(item, key, depth+1); value != nil {
					return value
				}
			}
		} else if value := mapNodeDepth(merged, key, depth+1); value != nil {
			return value
		}
	}
	return nil
}

func nodeStringMap(node *yaml.Node) map[string]string {
	result := map[string]string{}
	fillStringMap(node, result, 0)
	return result
}

func fillStringMap(node *yaml.Node, result map[string]string, depth int) {
	if node == nil || depth > 32 {
		return
	}
	if node.Kind == yaml.AliasNode {
		fillStringMap(node.Alias, result, depth+1)
		return
	}
	if node.Kind != yaml.MappingNode {
		return
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value != "<<" {
			continue
		}
		merged := node.Content[index+1]
		if merged.Kind == yaml.SequenceNode {
			for item := len(merged.Content) - 1; item >= 0; item-- {
				fillStringMap(merged.Content[item], result, depth+1)
			}
		} else {
			fillStringMap(merged, result, depth+1)
		}
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if key != "<<" {
			result[key] = node.Content[index+1].Value
		}
	}
}
