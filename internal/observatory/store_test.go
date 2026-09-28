package observatory

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func testRunSpec(id RunID) RunSpec {
	return RunSpec{
		RunID:      id,
		ScenarioID: "package-repair-control",
		Topology:   TopologySharedMessages,
		Seed:       7,
		BehaviorBundle: BehaviorBundle{
			EngineVersion:         "engine-v1",
			MonitorVersion:        "monitor-v1",
			ContainmentVersion:    "containment-v1",
			EvaluatorVersion:      "evaluator-v1",
			PolicyProtocolVersion: "policy-v1",
			BuildDigest:           strings.Repeat("a", 64),
		},
		ProtocolVersion: 1,
		Actors: []ActorSpec{{
			ID:           "agent-a",
			Role:         "repairer",
			Policy:       PolicyIdentity{ID: "honest", Digest: strings.Repeat("b", 64)},
			Capabilities: []Capability{"inspect", "edit"},
			ActionBudget: 8,
			SpendBudget:  10,
		}},
		Limits: RunLimits{MaxTicks: 20, MaxTotalActions: 100, MaxOutputBytes: 4096},
	}
}

func appendNoAction(t *testing.T, writer *RunWriter, tick uint64) {
	t.Helper()
	if err := writer.AppendDecision(DecisionRecord{
		Tick: tick, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionNoAction,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunIDRejectsPathComponents(t *testing.T) {
	for _, invalid := range []string{"", ".", "../escape", "a/b", "-leading", " space"} {
		if _, err := ParseRunID(invalid); err == nil {
			t.Errorf("ParseRunID(%q) succeeded; want error", invalid)
		}
	}
	if _, err := ParseRunID("run-1.alpha"); err != nil {
		t.Fatalf("ParseRunID valid ID: %v", err)
	}
}

func TestRunSpecRejectsDuplicateActorsAndCapabilities(t *testing.T) {
	spec := testRunSpec("duplicate-actor")
	spec.Actors = append(spec.Actors, spec.Actors[0])
	if err := spec.Validate(); err == nil {
		t.Fatal("duplicate actor ID accepted")
	}

	spec = testRunSpec("duplicate-capability")
	spec.Actors[0].Capabilities = []Capability{"inspect", "inspect"}
	if err := spec.Validate(); err == nil {
		t.Fatal("duplicate capability accepted")
	}
}

func TestStoreSeparatesPublicAndTruthStreams(t *testing.T) {
	for _, record := range []any{PublicEvent{}, MonitorObservation{}} {
		typ := reflect.TypeOf(record)
		for _, truthField := range []string{"Truth", "ExpectedDigest", "ActualDigest", "GroundTruth"} {
			if _, ok := typ.FieldByName(truthField); ok {
				t.Fatalf("%s exposes evaluator field %q", typ.Name(), truthField)
			}
		}
	}
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(testRunSpec("truth-separation"))
	if err != nil {
		t.Fatal(err)
	}
	public := PublicEvent{
		Tick:       1,
		ActorID:    "agent-a",
		Kind:       "artifact_created",
		IntentKind: IntentEdit,
		Outcome:    "accepted",
		Path:       "src/repair.go",
		Message:    "ready for review",
	}
	if err := writer.AppendPublic(public); err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendTruth(TruthRecord{
		Tick:           1,
		FactKind:       "ground_truth_sentinel",
		ExpectedDigest: strings.Repeat("c", 64),
		ActualDigest:   strings.Repeat("d", 64),
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendDecision(DecisionRecord{
		Tick:     1,
		ActorID:  "agent-a",
		PolicyID: "honest",
		Kind:     DecisionIntent,
		Intent:   &Intent{Kind: IntentEdit, Path: "src/repair.go", Content: "fixed"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Finalize(true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify("truth-separation"); err != nil {
		t.Fatalf("verify completed run: %v", err)
	}

	dir := filepath.Join(store.root, "truth-separation")
	publicBytes, err := os.ReadFile(filepath.Join(dir, "public.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	truthBytes, err := os.ReadFile(filepath.Join(dir, "truth.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicBytes, []byte("ground_truth_sentinel")) || bytes.Contains(publicBytes, []byte("expected_digest")) {
		t.Fatalf("public stream contains truth fields: %s", publicBytes)
	}
	if !bytes.Contains(truthBytes, []byte("ground_truth_sentinel")) {
		t.Fatalf("truth stream missing sentinel: %s", truthBytes)
	}
	monitorBytes, err := json.Marshal(MonitorObservation{Sequence: 1, Tick: 1, EventKind: "artifact_created", Outcome: "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(monitorBytes, []byte("ground_truth_sentinel")) || bytes.Contains(monitorBytes, []byte("expected_digest")) {
		t.Fatalf("monitor projection contains truth fields: %s", monitorBytes)
	}
}

func TestInvalidUTF8IsRejectedBeforeAppend(t *testing.T) {
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(testRunSpec("invalid-utf8"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendPublic(PublicEvent{Kind: "message", Outcome: "accepted", Message: string([]byte{0xff})}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("AppendPublic error = %v, want ErrInvalidRecord", err)
	}
	if err := writer.AppendPublic(PublicEvent{Kind: "message", Outcome: "accepted", Message: "valid"}); err != nil {
		t.Fatal(err)
	}
	appendNoAction(t, writer, 1)
	if _, err := writer.Finalize(true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify("invalid-utf8"); err != nil {
		t.Fatalf("valid record after rejected input did not verify: %v", err)
	}
}

func TestCanonicalHashesAreStable(t *testing.T) {
	create := func(root string) RunSeal {
		store, err := NewRunStore(root)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := store.Reserve(testRunSpec("stable-hash"))
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.AppendPublic(PublicEvent{Tick: 1, Kind: "task_started", Outcome: "accepted"}); err != nil {
			t.Fatal(err)
		}
		appendNoAction(t, writer, 1)
		seal, err := writer.Finalize(true)
		if err != nil {
			t.Fatal(err)
		}
		return seal
	}
	first := create(t.TempDir())
	second := create(t.TempDir())
	if first != second {
		t.Fatalf("identical records produced different seals: first=%#v second=%#v", first, second)
	}
}

func TestDecisionVariantsAreValidatedAndStored(t *testing.T) {
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(testRunSpec("decision-variants"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendDecision(DecisionRecord{
		Tick: 1, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionIntent,
		Intent: &Intent{Kind: IntentInspect, Path: "src/repair.go"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, decision := range []DecisionRecord{
		{Tick: 2, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionNoAction},
		{Tick: 3, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionPolicyFault, FaultCode: "timeout"},
		{Tick: 4, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionSuppressed, SuppressionReason: "capability_revoked"},
	} {
		if err := writer.AppendDecision(decision); err != nil {
			t.Fatalf("append %s decision: %v", decision.Kind, err)
		}
	}
	if err := writer.AppendDecision(DecisionRecord{
		Tick: 5, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionNoAction, FaultCode: "timeout",
	}); err == nil {
		t.Fatal("contradictory decision fields were accepted")
	}
	seal, err := writer.Finalize(true)
	if err != nil {
		t.Fatal(err)
	}
	if seal.DecisionCount != 4 {
		t.Fatalf("decision count = %d, want 4", seal.DecisionCount)
	}
	if _, err := store.Verify("decision-variants"); err != nil {
		t.Fatalf("verify decision variants: %v", err)
	}
}

func TestCompletedRunRequiresDecisionTrace(t *testing.T) {
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(testRunSpec("empty-decision-trace"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Finalize(true); !errors.Is(err, ErrIncompleteRun) {
		t.Fatalf("Finalize error = %v, want ErrIncompleteRun", err)
	}
	if _, err := store.Verify("empty-decision-trace"); !errors.Is(err, ErrIncompleteRun) {
		t.Fatalf("Verify error = %v, want ErrIncompleteRun", err)
	}
}

func TestVerifyRejectsDecisionsOutsideRunContract(t *testing.T) {
	cases := map[string][]DecisionRecord{
		"unknown actor": {{Tick: 1, ActorID: "agent-b", PolicyID: "honest", Kind: DecisionNoAction}},
		"wrong policy":  {{Tick: 1, ActorID: "agent-a", PolicyID: "other", Kind: DecisionNoAction}},
		"out of range":  {{Tick: 21, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionNoAction}},
		"duplicate": {
			{Tick: 1, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionNoAction},
			{Tick: 1, ActorID: "agent-a", PolicyID: "honest", Kind: DecisionSuppressed, SuppressionReason: "budget_exhausted"},
		},
	}
	for name, decisions := range cases {
		t.Run(name, func(t *testing.T) {
			store, err := NewRunStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			writer, err := store.Reserve(testRunSpec("invalid-decision"))
			if err != nil {
				t.Fatal(err)
			}
			for _, decision := range decisions {
				if err := writer.AppendDecision(decision); err != nil {
					t.Fatalf("append structurally valid decision: %v", err)
				}
			}
			if _, err := writer.Finalize(true); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Verify("invalid-decision"); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Verify error = %v, want ErrIntegrity", err)
			}
		})
	}
}

func TestTamperedStreamsFailVerification(t *testing.T) {
	mutations := map[string]func([]byte) []byte{
		"changed": func(data []byte) []byte {
			return bytes.Replace(data, []byte("first"), []byte("other"), 1)
		},
		"removed": func(data []byte) []byte {
			lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
			return append(bytes.Clone(lines[1]), '\n')
		},
		"reordered": func(data []byte) []byte {
			lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
			return bytes.Join([][]byte{lines[1], lines[0], nil}, []byte{'\n'})
		},
		"truncated": func(data []byte) []byte {
			return bytes.Clone(data[:len(data)-3])
		},
		"crlf": func(data []byte) []byte {
			return bytes.ReplaceAll(data, []byte{'\n'}, []byte{'\r', '\n'})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store := createCompleteRun(t, "tamper-"+name, true)
			path := filepath.Join(store.root, "tamper-"+name, "public.jsonl")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, mutate(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Verify(RunID("tamper-" + name)); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Verify error = %v, want ErrIntegrity", err)
			}
		})
	}
}

func TestIncompleteRunsCannotVerify(t *testing.T) {
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(testRunSpec("explicit-incomplete"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Finalize(false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify("explicit-incomplete"); !errors.Is(err, ErrIncompleteRun) {
		t.Fatalf("Verify error = %v, want ErrIncompleteRun", err)
	}

	writer, err = store.Reserve(testRunSpec("corrupt-incomplete"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendPublic(PublicEvent{Kind: "task_started", Outcome: "accepted"}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Finalize(false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.root, "corrupt-incomplete", "public.jsonl"), []byte("damaged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify("corrupt-incomplete"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corrupt incomplete Verify error = %v, want ErrIntegrity", err)
	}

	writer, err = store.Reserve(testRunSpec("crashed-run"))
	if err != nil {
		t.Fatal(err)
	}
	writer.closeStreams()
	if err := os.WriteFile(filepath.Join(store.root, "crashed-run", "spec.json"), []byte("{partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify("crashed-run"); !errors.Is(err, ErrIncompleteRun) {
		t.Fatalf("Verify error = %v, want ErrIncompleteRun", err)
	}
}

func TestRejectedOversizedRecordPreventsFinalization(t *testing.T) {
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(testRunSpec("oversized-record"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendPublic(PublicEvent{Kind: "message", Outcome: "accepted", Message: strings.Repeat("x", maxRecordBytes)}); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("AppendPublic error = %v, want ErrFileTooLarge", err)
	}
	if _, err := writer.Finalize(true); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("Finalize error = %v, want ErrFileTooLarge", err)
	}
	if _, err := store.Verify("oversized-record"); !errors.Is(err, ErrIncompleteRun) {
		t.Fatalf("Verify error = %v, want ErrIncompleteRun", err)
	}
}

func TestMissingStreamAfterSealIsIntegrityFailure(t *testing.T) {
	store := createCompleteRun(t, "missing-sealed-stream", false)
	if err := os.Remove(filepath.Join(store.root, "missing-sealed-stream", "public.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify("missing-sealed-stream"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Verify error = %v, want ErrIntegrity", err)
	}
}

func TestRunIDReservationIsAtomic(t *testing.T) {
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 24
	start := make(chan struct{})
	type result struct {
		writer *RunWriter
		err    error
	}
	results := make(chan result, contenders)
	var workers sync.WaitGroup
	workers.Add(contenders)
	for range contenders {
		go func() {
			defer workers.Done()
			<-start
			writer, err := store.Reserve(testRunSpec("one-owner"))
			results <- result{writer: writer, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	wins := 0
	for result := range results {
		if result.err == nil {
			wins++
			appendNoAction(t, result.writer, 1)
			if _, err := result.writer.Finalize(true); err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(result.err, ErrRunExists) {
			t.Fatalf("unexpected reservation error: %v", result.err)
		}
	}
	if wins != 1 {
		t.Fatalf("successful reservations = %d, want 1", wins)
	}
	if _, err := store.Verify("one-owner"); err != nil {
		t.Fatalf("winning run invalid after competing reservations: %v", err)
	}
}

func TestExistingRunIDWithDifferentSpecIsNotOverwritten(t *testing.T) {
	store := createCompleteRun(t, "immutable-id", false)
	different := testRunSpec("immutable-id")
	different.ScenarioID = "different-scenario"
	if _, err := store.Reserve(different); !errors.Is(err, ErrRunExists) {
		t.Fatalf("Reserve error = %v, want ErrRunExists", err)
	}
	if _, err := store.Verify("immutable-id"); err != nil {
		t.Fatalf("existing run was modified: %v", err)
	}
}

func createCompleteRun(t *testing.T, id string, twoEvents bool) *RunStore {
	t.Helper()
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(testRunSpec(RunID(id)))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendPublic(PublicEvent{Tick: 1, Kind: "artifact_created", Outcome: "accepted", Path: "first"}); err != nil {
		t.Fatal(err)
	}
	if twoEvents {
		if err := writer.AppendPublic(PublicEvent{Tick: 2, Kind: "artifact_created", Outcome: "accepted", Path: "second"}); err != nil {
			t.Fatal(err)
		}
	}
	appendNoAction(t, writer, 1)
	if _, err := writer.Finalize(true); err != nil {
		t.Fatal(err)
	}
	return store
}
