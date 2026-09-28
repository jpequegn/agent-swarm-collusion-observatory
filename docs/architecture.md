# Architecture and trust boundaries

## V1 shape

The observatory is an offline, deterministic lab for comparing shared-message and hierarchical-delegation swarms on the same finite package-repair task. It records coordination failures, repeated tool calls, hidden or indirect shared artifacts, verification, budget exhaustion, and safe bailout. Scenarios are synthetic and use allowlisted actions; they never run commands against a real repository.

One Go engine owns virtual time, action validation, state reduction, event storage, monitor projections, containment, replay, evaluation, CLI, and the local UI. Python is limited to checked-in policy implementations that propose typed actions over a versioned JSONL protocol. The Go engine remains authoritative and rejects malformed, unauthorized, or over-budget actions.

## Evidence and information flow

- Public events and evaluator-only truth are distinct types and persisted streams.
- Agents see only their allowlisted observations. The independent monitor receives a separate, contiguous projection with no truth or hidden global sequence gaps.
- Evaluation sees truth only after a run is complete and its seal verifies.
- Run IDs are reserved atomically and are never overwritten. A seal binds the run specification, behavior bundle, event streams, decision trace, counts, and completion state.
- Replay verifies the source seal and complete decision trace, then recomputes derived output under the same supported behavior bundle. Unsupported bundles fail closed. Replay does not rerun Python.
- If final seal publication succeeds but directory synchronization reports an error, the result is indeterminate; verify the same run ID before retrying.

Determinism is guaranteed for the same complete recorded decision trace and behavior bundle. Host-dependent subprocess timeouts can change a live run and are recorded as explicit faults; identical run specifications alone do not promise identical live outcomes.

## Local policy boundary

The Go host starts only bundled policies and bounds their protocol messages, output, stderr, execution time, and action budgets. It terminates a policy process group on timeout. These controls do not create an OS sandbox. Arbitrary third-party policy code is not supported and must not be run.

## UI boundary

The UI binds only to loopback. Read endpoints are read-only; state changes use JSON POST requests with exact Host/Origin checks and an anti-CSRF token. Truth-bearing output requires an explicit evaluator projection for a complete verified run. No UI or simulator component calls a remote service or model API.

## Explicit V1 exclusions

No live Git or shell execution, database, broker, distributed scheduler, arbitrary plugin system, model API, telemetry backend, signed attestation, or historical engine loader. The hash chain detects tampering only while the original seal remains trusted; it is not a signature and cannot protect against replacement of both data and seal.
