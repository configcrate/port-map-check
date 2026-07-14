# Contributing

Thanks for helping improve Port Map Check.

## Before opening a change

- Open an issue for a new parser, rule, or behavior change.
- Include a minimal configuration that demonstrates the problem.
- Explain whether the configuration is always invalid or merely suspicious.
- Prefer a warning when the relevant platform allows a valid runtime interpretation that static analysis cannot exclude.

## Local checks

```bash
gofmt -w .
go test ./...
go vet ./...
```

New rules should include:

1. a failing/broken fixture or focused unit input;
2. a corrected case that produces no finding;
3. a stable rule code;
4. a concise explanation and actionable suggestion;
5. README documentation, including known false-positive boundaries.

Do not add network access or execute scanned repository content. Open an issue first if a feature appears to require runtime inspection.
