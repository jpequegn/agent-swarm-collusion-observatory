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

## Bundled policies

The Go adapter starts only the reviewed policy catalog in `python/observatory_policies/runner.py`. Policies receive one versioned JSONL request containing the current actor's allowlisted observation, capabilities, and remaining action budget. The adapter bounds request and response sizes, stderr, wall-clock time, and terminates the whole subprocess group on timeout. Policy replies are proposals; the Go engine still enforces permissions, budgets, and scenario rules. There is no plugin loading, network access, or model API.

## Evaluation

Use `internal/benchmark.EvaluateRun` to produce a versioned report for a complete, integrity-verified run. Use `ComparePairedRuns` to compare the shared-message and hierarchical runs without collapsing their results into one score. Metric definitions and JSON fields are documented in [docs/evaluation.md](docs/evaluation.md).

## Safety boundary

Policies propose typed actions to a Go-owned simulator. They do not execute shell commands against a real repository. The subprocess limits are resource controls, not an OS sandbox; do not use them to run untrusted Python. Only checked-in policy code is supported. See [docs/architecture.md](docs/architecture.md) for the data boundaries and replay guarantees.
