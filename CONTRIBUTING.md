# Contributing to BouncerFox CLI

Thank you for your interest in contributing to BouncerFox CLI.

## Getting Started

```bash
git clone https://github.com/bouncerfox/cli.git
cd cli
go build -o bouncerfox ./cmd/bouncerfox
go test ./... -race
```

Requires Go 1.25+.

## Development Workflow

1. Fork the repo and create a feature branch from `main`.
2. Write a failing test for your change.
3. Implement the change until tests pass.
4. Run `go test ./... -race` and `go vet ./...` before pushing.
5. Open a pull request against `main`.

## Running Linters

```bash
# Install golangci-lint v2
# See https://golangci-lint.run/usage/install/
golangci-lint run
```

## Adding a New Rule

1. Add the rule definition to `pkg/rules/registry.go`.
2. Implement the check function in the appropriate file under `pkg/rules/` (`sec.go`, `qa.go`, `cfg.go`, or `ps.go`).
3. Add tests in the corresponding `_test.go` file.
4. Register the rule in the `Registry` slice (order matters for rules that share cached state).

## Custom Rule Primitives

Custom rules use match primitives defined in `pkg/custom/`. To add a new primitive:

1. Add the matcher to `pkg/custom/compiler.go`.
2. Add tests in `pkg/custom/compiler_test.go`.
3. Document the primitive in the README under Custom Rules.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- All regex must be RE2 compatible (no lookaheads or backreferences).
- Test files live alongside the code they test.
- Prefer table-driven tests.

## Reporting Issues

- Use [GitHub Issues](https://github.com/bouncerfox/cli/issues) for bugs and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
