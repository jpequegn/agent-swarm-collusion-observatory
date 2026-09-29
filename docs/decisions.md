# Implementation decisions

This record explains the shipped design for [project-ideas #267](https://github.com/jpequegn/project-ideas/issues/267). The initial plan and trust boundaries are in [the architecture guide](architecture.md). Each decision links to its implementation issue and merged pull request in the [project tracker](project-tracker.md).

## Keep the simulator offline and Go-owned

The Go engine owns time, state transitions, validation, evidence, monitoring, containment, evaluation, replay, and user interfaces. Python policies propose typed actions through a bounded JSONL protocol. The environment uses synthetic package-repair tasks instead of executing agents against a live repository. This keeps runs inspectable and reproducible without credentials, model APIs, or real-world side effects. Issues [#1](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/1), [#3](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/3), [#4](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/4), and [#5](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/5) track those boundaries.

The Python subprocess limits are resource controls, not an operating-system sandbox. Only the checked-in policy catalog is supported.

## Record decisions for replay

Replay consumes the complete, verified decision trace and applies the supported Go behavior bundle. It does not rerun Python. That makes replay independent of later policy process timing, but it also means V1 does not claim that the same run specification alone will produce the same live outcome. A host-dependent policy timeout can change a live run. The timeout is recorded as a policy fault. Unsupported behavior bundles fail closed instead of loading historical engine versions. See issue [#3](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/3) and the [replay guarantees](architecture.md#replay-and-determinism-claims).

## Keep public evidence separate from evaluator truth

The store uses distinct public, truth, decision, and monitor streams. Agents and the independent monitor receive explicit projections. The evaluator can read truth only after a run completes and its seal verifies. The seal detects changes while the original seal remains trusted. It is not a signature, and it cannot detect an attacker replacing both evidence and seal. Issues [#2](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/2), [#6](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/6), and [#9](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/9) implement these rules.

## Report separate metrics instead of one score

The evaluator reports task quality, verification evidence, coordination, duplicate actions, abstention, monitor detection, containment, and replay as separate fields. A single score would hide tradeoffs such as successful work with weak evidence or a monitor that detects attacks but raises false positives. Paired runs compare the same task and configuration under shared-message and hierarchical topologies. See issue [#7](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/7) and the [metric definitions](evaluation.md).

## Use a local interface with explicit truth access

The CLI is the scriptable interface. The browser UI binds to IPv4 loopback and uses same-origin JSON mutations with Host, Origin, cookie, and CSRF checks. Run details and integrity responses omit truth records. The UI exposes evaluator truth through a separate request only after store verification. The embedded assets avoid a build toolchain and remote dependencies. Issues [#8](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/8) and [#9](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/9) track the user workflows.

## Keep V1 small

V1 has no database, broker, distributed scheduler, arbitrary plugin system, live shell or Git execution, model API, telemetry backend, signed attestation, or historical engine loader. The [architecture guide](architecture.md#explicit-v1-exclusions) lists these limits. Issue [#10](https://github.com/jpequegn/agent-swarm-collusion-observatory/issues/10) adds the reproducible release gate and this project record.
