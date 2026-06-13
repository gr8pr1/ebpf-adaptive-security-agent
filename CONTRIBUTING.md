# Contributing

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ebpf-host-monitor.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit with clear messages: `git commit -m "Add feature: description"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

```bash
cd host/ebpf-agent
go mod download
make all
sudo ./ebpf-agent
```

## Code Style

### Go
- Follow standard Go conventions
- Run `go fmt` before committing
- Keep functions focused and small

### eBPF C
- Follow Linux kernel coding style
- Keep programs simple and verifiable (eBPF verifier is strict)
- Gate new features behind `#ifdef MONITOR_*` compile-time flags

### YAML
- Use 2-space indentation
- Validate syntax before committing

## Adding a New Monitor

1. **BPF**: Add a new tracepoint program and ringbuf `emit_event()` / `emit_exec_event()` call in `bpf/exec.bpf.c`. Gate it behind a `MONITOR_*` flag. Use the 72-byte `ebpf_event` header; exec events may append a filename tail.
2. **Makefile**: Add the new flag to the Makefile.
3. **Config**: Add the tracepoint and metric entries in `config.yaml`.
4. **Aggregator**: Add the event type mapping in `internal/aggregator/aggregator.go`.
5. **MITRE Mapper**: Add the technique mapping in `internal/mitre/mitre.go`.
6. **Tests**: Update `internal/config/config_test.go`.
7. **Docs**: Update `README.md`, `ARCHITECTURE.md`, and log the change in `state.md`.

## Testing

```bash
# Run unit tests
make test

# Run integration replay harness
go test -tags=integration ./internal/integration/...

# Test the agent manually
sudo ./ebpf-agent

# Generate events
ls && sudo ls && cat /etc/passwd

# Check metrics
curl http://localhost:9110/metrics | grep ebpf_
```

## Pull Request Guidelines

- Clear and descriptive title
- Explain what and why
- Describe how you tested
- Update relevant docs
- Keep commits logical and atomic

## Reporting Issues

Include:
- OS and kernel version (`uname -r`)
- Go version (`go version`)
- Steps to reproduce
- Relevant logs (`sudo journalctl -u ebpf-agent`)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
