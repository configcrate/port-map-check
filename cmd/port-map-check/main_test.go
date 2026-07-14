package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestRunExitThresholds(t *testing.T) {
	broken := filepath.Join("..", "..", "examples", "broken-stack")
	healthy := filepath.Join("..", "..", "examples", "healthy-stack")
	getenv := func(string) string { return "" }
	for _, test := range []struct {
		args []string
		want int
	}{
		{[]string{"scan", healthy}, 0},
		{[]string{"scan", broken}, 1},
		{[]string{"scan", broken, "--fail-on", "never", "--format", "json"}, 0},
		{[]string{"scan", healthy, "--format", "nope"}, 2},
	} {
		var stdout, stderr bytes.Buffer
		if got := run(test.args, getenv, &stdout, &stderr); got != test.want {
			t.Fatalf("run(%v) = %d, want %d; stderr=%s", test.args, got, test.want, stderr.String())
		}
	}
}

func TestActionArgs(t *testing.T) {
	env := map[string]string{"GITHUB_ACTIONS": "true", "INPUT_PATH": "src", "INPUT_FORMAT": "html", "INPUT_OUTPUT": "report.html", "INPUT_FAIL-ON": "warning", "INPUT_EXCLUDE": "vendor/**, fixtures/**"}
	getenv := func(key string) string { return env[key] }
	got := actionArgs(nil, getenv)
	want := []string{"scan", "src", "--format", "html", "--output", "report.html", "--fail-on", "warning", "--exclude", "vendor/**", "--exclude", "fixtures/**"}
	if len(got) != len(want) {
		t.Fatalf("actionArgs = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("actionArgs[%d] = %q, want %q", index, got[index], want[index])
		}
	}
}
