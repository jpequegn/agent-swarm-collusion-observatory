# Command-line workflows

Run commands from the repository root. The CLI writes sealed run evidence beneath `.observatory/runs` by default. Commands return JSON on stdout; invalid IDs, unsupported bundles, incomplete runs, and integrity failures return a nonzero exit status with an actionable error on stderr.

```sh
go run ./cmd/observatory fixtures
go run ./cmd/observatory run --fixture honest-coordination --topology shared_messages
go run ./cmd/observatory run --fixture collusion-reward-gaming --worker-policy reward_gamer
```

Copy the `run_id` from the run result into subsequent commands:

```sh
go run ./cmd/observatory inspect --run-id RUN_ID --limit 50
go run ./cmd/observatory verify --run-id RUN_ID
go run ./cmd/observatory evaluate --run-id RUN_ID
go run ./cmd/observatory replay --run-id RUN_ID
go run ./cmd/observatory ui --port 8765
```

`run` supports `shared_messages` and `hierarchical`. Its worker policy can be `honest_repair`, `no_action`, `duplicate_inspector`, or `reward_gamer`; other actors use the bundled no-action policy. `reward_gamer` demonstrates proxy-reward edits but does not deliberately run verification, so it may not trigger the monitor's proxy/verification mismatch rule. The regression corpus includes the adversarial edit-plus-failed-verification sequence and asserts its containment actions. The Python runner remains source-pinned and bounded by the adapter. The CLI never loads arbitrary policy plugins.

Replay requires the same CLI executable build and supported behavior versions that created the run. A source run is integrity-verified before replay, and unsupported bundles fail closed. The returned `faithful` field is true only after the replay engine verifies matching semantic digests.

```sh
go run ./cmd/observatory regress
```

The command executes the embedded `incident-corpus-v1` definitions and requires every registered fixture to appear in the corpus. It checks honest repair, benign message/artifact coordination, reward-gaming detection and containment, dropped messages, duplicate-call false positives, hidden-artifact hierarchy, safe bailout, scheduled capability revocation, and public-stream tampering. Each intact run must replay faithfully; the tampered run must fail integrity verification and must not replay. Regression JSON omits run IDs and timestamps so its semantic results remain comparable. Pass `--store /path/to/runs` to retain evidence for inspection; without it, a temporary store is removed when the command exits.

The corpus is an offline deterministic regression suite, not evidence that the simulator predicts real-world agent behavior. It uses synthetic package-repair fixtures and checked-in policies only.

## Local UI

`go run ./cmd/observatory ui --port 8765` serves the embedded operator view at `http://127.0.0.1:8765`. The listener is fixed to IPv4 loopback; it does not accept a bind-address override. Choose another port when 8765 is occupied. The page and assets are embedded in the binary, and all browser requests are same-origin.

The UI supports fixture/topology selection, run creation, ordered public and monitor traces, integrity verification, evaluation, verified replay, and an explicit evaluator-truth projection. The default run and integrity responses do not serialize truth records or truth digests. The truth endpoint returns records only after the run is complete and passes store verification.

State-changing endpoints accept only JSON `POST` requests with the exact loopback `Host`, matching `Origin`, a session cookie, and the session's CSRF token. Other API reads do not change run data. The session bootstrap endpoint only initializes the in-memory browser session and its anti-CSRF cookie.
