package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/configcrate/port-map-check/internal/analyze"
	"github.com/configcrate/port-map-check/internal/model"
	"github.com/configcrate/port-map-check/internal/report"
	"github.com/configcrate/port-map-check/internal/scan"
)

var version = "dev"

type config struct {
	format      string
	output      string
	failOn      string
	maxFileSize int64
	exclude     stringList
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	args = actionArgs(args, getenv)
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		printUsage(stdout)
		return 0
	}
	if len(args) == 0 {
		args = []string{"scan", "."}
	}
	if args[0] != "scan" {
		fmt.Fprintf(stderr, "error: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("port-map-check scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var cfg config
	flags.StringVar(&cfg.format, "format", "text", "report format: text, json, or html")
	flags.StringVar(&cfg.output, "output", "", "write report to this file instead of stdout")
	flags.StringVar(&cfg.failOn, "fail-on", "error", "exit 1 on: error, warning, or never")
	flags.Int64Var(&cfg.maxFileSize, "max-file-size", 2<<20, "maximum candidate file size in bytes")
	flags.Var(&cfg.exclude, "exclude", "repository-relative path glob to exclude (repeatable; ** crosses directories)")
	flags.Usage = func() { printScanUsage(flags.Output(), flags) }
	if err := flags.Parse(normalizeScanArgs(args[1:])); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if cfg.format != "text" && cfg.format != "json" && cfg.format != "html" {
		fmt.Fprintln(stderr, "error: --format must be text, json, or html")
		return 2
	}
	if cfg.failOn != "error" && cfg.failOn != "warning" && cfg.failOn != "never" {
		fmt.Fprintln(stderr, "error: --fail-on must be error, warning, or never")
		return 2
	}
	if cfg.maxFileSize < 1 {
		fmt.Fprintln(stderr, "error: --max-file-size must be positive")
		return 2
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "error: scan accepts at most one repository path")
		return 2
	}
	root := "."
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(stderr, "error: resolve root: %v\n", err)
		return 2
	}
	result, err := scan.Repository(absoluteRoot, scan.Options{MaxFileSize: cfg.maxFileSize, Exclude: cfg.exclude})
	if err != nil {
		fmt.Fprintf(stderr, "error: scan repository: %v\n", err)
		return 2
	}
	value := analyze.Build(absoluteRoot, result)
	output := stdout
	var file *os.File
	if cfg.output != "" {
		if directory := filepath.Dir(cfg.output); directory != "." {
			if err := os.MkdirAll(directory, 0o755); err != nil {
				fmt.Fprintf(stderr, "error: create output directory: %v\n", err)
				return 2
			}
		}
		file, err = os.Create(cfg.output)
		if err != nil {
			fmt.Fprintf(stderr, "error: create report: %v\n", err)
			return 2
		}
		defer file.Close()
		output = file
	}
	if err := report.Write(output, value, cfg.format); err != nil {
		fmt.Fprintf(stderr, "error: write report: %v\n", err)
		return 2
	}
	if cfg.output != "" {
		fmt.Fprintf(stderr, "port-map-check: wrote %s report to %s\n", cfg.format, cfg.output)
	}
	if summaryPath := getenv("GITHUB_STEP_SUMMARY"); summaryPath != "" {
		_ = writeGitHubSummary(summaryPath, value)
	}
	switch cfg.failOn {
	case "error":
		if value.HasErrors() {
			return 1
		}
	case "warning":
		if value.HasErrors() || value.HasWarnings() {
			return 1
		}
	}
	return 0
}

func normalizeScanArgs(args []string) []string {
	valueFlags := map[string]bool{"--format": true, "--output": true, "--fail-on": true, "--max-file-size": true, "--exclude": true}
	var options, positional []string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			positional = append(positional, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positional = append(positional, argument)
			continue
		}
		options = append(options, argument)
		name := argument
		if equal := strings.IndexByte(argument, '='); equal >= 0 {
			name = argument[:equal]
		}
		if valueFlags[name] && !strings.Contains(argument, "=") && index+1 < len(args) {
			index++
			options = append(options, args[index])
		}
	}
	return append(options, positional...)
}

func actionArgs(args []string, getenv func(string) string) []string {
	if len(args) > 0 || getenv("GITHUB_ACTIONS") != "true" {
		return args
	}
	path := strings.TrimSpace(getenv("INPUT_PATH"))
	if path == "" {
		path = "."
	}
	result := []string{"scan", path}
	for _, pair := range [][2]string{{"INPUT_FORMAT", "--format"}, {"INPUT_OUTPUT", "--output"}, {"INPUT_FAIL-ON", "--fail-on"}} {
		if value := strings.TrimSpace(getenv(pair[0])); value != "" {
			result = append(result, pair[1], value)
		}
	}
	for _, value := range strings.FieldsFunc(getenv("INPUT_EXCLUDE"), func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, "--exclude", value)
		}
	}
	return result
}

func writeGitHubSummary(path string, value model.Report) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := fmt.Fprintf(file, "## Port Map Check\n\n| Resources | Ports | References | Errors | Warnings |\n| ---: | ---: | ---: | ---: | ---: |\n| %d | %d | %d | %d | %d |\n\n", value.Summary.Resources, value.Summary.Ports, value.Summary.References, value.Summary.Errors, value.Summary.Warnings); err != nil {
		return err
	}
	limit := len(value.Findings)
	if limit > 20 {
		limit = 20
	}
	for _, finding := range value.Findings[:limit] {
		icon := "⚠️"
		if finding.Severity == model.SeverityError {
			icon = "❌"
		}
		if _, err := fmt.Fprintf(file, "- %s `%s` %s", icon, finding.Code, finding.Message); err != nil {
			return err
		}
		if finding.Source != "" {
			if _, err := fmt.Fprintf(file, " — `%s`", finding.Source); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(file); err != nil {
			return err
		}
	}
	return nil
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Port Map Check finds broken port and service wiring across repository configuration.")
	fmt.Fprintln(writer, "\nUsage:\n  port-map-check scan [path] [flags]\n  port-map-check version")
}

func printScanUsage(writer io.Writer, flags *flag.FlagSet) {
	printUsage(writer)
	fmt.Fprintln(writer, "\nScan flags:")
	flags.PrintDefaults()
}
