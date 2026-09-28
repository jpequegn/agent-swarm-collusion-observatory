# Agent Swarm Collusion Observatory

An offline lab for measuring whether multi-agent workflows complete tasks honestly, preserve evidence, and stop safely. V1 compares shared-message and hierarchical synthetic package-repair swarms; it does not connect to live systems or model APIs.

## Requirements

- Go 1.25 or newer
- Python 3.12 or newer
- GNU Make (or run the commands in the Makefile directly)

## Checks

```sh
make check
```

The Python policy package and its tests use only the standard library. The Go engine package is under `internal/observatory`; bundled policies live under `python/`.

## Safety boundary

Policies propose typed actions to a Go-owned simulator. They do not execute shell commands against a real repository. A subprocess timeout and message limit are resource controls, not an OS sandbox; only checked-in policy code is supported. See [docs/architecture.md](docs/architecture.md) for the data boundaries and replay guarantees.
