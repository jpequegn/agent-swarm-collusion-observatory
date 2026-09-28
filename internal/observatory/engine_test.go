package observatory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type engineTestState struct {
	Edits uint64 `json:"edits"`
}

type engineTestScenario struct {
	completeAt uint64
	skipActor  ActorID
}

func (s engineTestScenario) ID() string { return "package-repair-control" }

func (s engineTestScenario) InitialState(int64) engineTestState { return engineTestState{} }

func (s engineTestScenario) Complete(state engineTestState) bool {
	return s.completeAt > 0 && state.Edits >= s.completeAt
}

func (s engineTestScenario) Eligible(_ engineTestState, actor ActorSpec, _ uint64) bool {
	return actor.ID != s.skipActor
}

func (s engineTestScenario) Observe(state engineTestState, _ ActorSpec, _ uint64) (json.RawMessage, error) {
	return json.Marshal(state)
}

func (s engineTestScenario) Reduce(state engineTestState, actor ActorSpec, tick uint64, intent Intent) (ScenarioTransition[engineTestState], error) {
	if intent.Kind != IntentEdit {
		return ScenarioTransition[engineTestState]{}, ScenarioFailure{Code: "unsupported_intent"}
	}
	state.Edits++
	return ScenarioTransition[engineTestState]{
		NextState: state,
		PublicEvents: []PublicEvent{{
			Tick: tick, ActorID: actor.ID, Kind: "edit_applied", IntentKind: intent.Kind,
			Outcome: "accepted", Path: intent.Path, ContentDigest: digestBytes([]byte(intent.Content)),
		}},
		TruthRecords: []TruthRecord{{Tick: tick, FactKind: "edit_count", ActorID: actor.ID, Value: true}},
	}, nil
}

type policyCall struct {
	actor       ActorID
	observation AgentObservation
}

type testPolicy struct {
	identity  PolicyIdentity
	proposal  PolicyProposal
	responses []policyResponse
	response  int
	calls     *[]policyCall
	cancel    context.CancelFunc
}

type policyResponse struct {
	proposal PolicyProposal
	err      error
}

func (p *testPolicy) Identity() PolicyIdentity { return p.identity }

func (p *testPolicy) Decide(_ context.Context, observation AgentObservation) (PolicyProposal, error) {
	if p.calls != nil {
		*p.calls = append(*p.calls, policyCall{actor: observation.ActorID, observation: observation})
	}
	if p.cancel != nil {
		p.cancel()
	}
	if p.response < len(p.responses) {
		response := p.responses[p.response]
		p.response++
		return response.proposal, response.err
	}
	return p.proposal, nil
}

func engineTestActor(id ActorID, capabilities ...Capability) ActorSpec {
	policyID := PolicyID("policy-" + string(id))
	return ActorSpec{
		ID: id, Role: "repairer", Policy: PolicyIdentity{ID: policyID, Digest: strings.Repeat("b", 64)},
		Capabilities: capabilities, ActionBudget: 8,
	}
}

func engineTestSetup(t *testing.T, actors []ActorSpec, scenario engineTestScenario, proposal PolicyProposal) (*RunStore, *Engine[engineTestState], RunSpec, *[]policyCall) {
	t.Helper()
	store, err := NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spec := testRunSpec("engine-test")
	spec.Actors = actors
	spec.Limits = RunLimits{MaxTicks: 4, MaxTotalActions: 20, MaxOutputBytes: 4096}
	calls := make([]policyCall, 0)
	policies := make(map[PolicyID]DecisionPolicy, len(actors))
	for _, actor := range actors {
		policies[actor.Policy.ID] = &testPolicy{identity: actor.Policy, proposal: proposal, calls: &calls}
	}
	engine := &Engine[engineTestState]{Store: store, Bundle: spec.BehaviorBundle, Scenario: scenario, Policies: policies}
	return store, engine, spec, &calls
}

func TestEngineFreezesObservationsAndSortsActors(t *testing.T) {
	actors := []ActorSpec{
		engineTestActor("agent-b", "edit"),
		engineTestActor("agent-a", "edit"),
	}
	proposal := PolicyProposal{Kind: DecisionIntent, Intent: &Intent{Kind: IntentEdit, Path: "src/fix.go", Content: "fixed"}}
	store, engine, spec, calls := engineTestSetup(t, actors, engineTestScenario{completeAt: 2}, proposal)
	result, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := []ActorID{(*calls)[0].actor, (*calls)[1].actor}; !reflect.DeepEqual(got, []ActorID{"agent-a", "agent-b"}) {
		t.Fatalf("policy call order = %v, want sorted actor order", got)
	}
	for _, call := range *calls {
		var observed engineTestState
		if err := json.Unmarshal(call.observation.Data, &observed); err != nil {
			t.Fatal(err)
		}
		if observed.Edits != 0 {
			t.Fatalf("actor %s saw mid-tick state with %d edits", call.actor, observed.Edits)
		}
	}
	run, err := store.ReadVerifiedRun(result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Seal.DecisionCount != 2 || run.Seal.TruthCount != 2 {
		t.Fatalf("unexpected evidence counts: decisions=%d truth=%d", run.Seal.DecisionCount, run.Seal.TruthCount)
	}
}

func TestEngineEnforcesActionBudgetAndCapability(t *testing.T) {
	t.Run("actor budget suppresses later calls", func(t *testing.T) {
		actor := engineTestActor("agent-a", "edit")
		actor.ActionBudget = 1
		proposal := PolicyProposal{Kind: DecisionIntent, Intent: &Intent{Kind: IntentEdit, Path: "src/fix.go", Content: "fixed"}}
		store, engine, spec, calls := engineTestSetup(t, []ActorSpec{actor}, engineTestScenario{}, proposal)
		spec.Limits.MaxTicks = 2
		result, err := engine.Run(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 1 {
			t.Fatalf("policy called %d times, want once", len(*calls))
		}
		run, err := store.ReadVerifiedRun(result.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if len(run.Decisions) != 2 || run.Decisions[1].Kind != DecisionSuppressed || run.Decisions[1].SuppressionReason != "actor_action_budget_exhausted" {
			t.Fatalf("unexpected budget trace: %#v", run.Decisions)
		}
	})

	t.Run("missing capability is rejected", func(t *testing.T) {
		actor := engineTestActor("agent-a", "inspect")
		proposal := PolicyProposal{Kind: DecisionIntent, Intent: &Intent{Kind: IntentEdit, Path: "src/fix.go", Content: "fixed"}}
		store, engine, spec, _ := engineTestSetup(t, []ActorSpec{actor}, engineTestScenario{completeAt: 1}, proposal)
		result, err := engine.Run(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		run, err := store.ReadVerifiedRun(result.RunID)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, event := range run.PublicEvents {
			if event.Kind == "intent_rejected" && event.ReasonCode == "capability_denied" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing capability rejection event: %#v", run.PublicEvents)
		}
	})
}

func TestEngineRecordsEveryDecisionVariant(t *testing.T) {
	actor := engineTestActor("agent-a", "edit")
	actor.ActionBudget = 1
	proposal := PolicyProposal{Kind: DecisionIntent, Intent: &Intent{Kind: IntentEdit, Path: "src/fix.go", Content: "fixed"}}
	store, engine, spec, _ := engineTestSetup(t, []ActorSpec{actor}, engineTestScenario{}, proposal)
	engine.Policies[actor.Policy.ID] = &testPolicy{
		identity: actor.Policy,
		proposal: proposal,
		responses: []policyResponse{
			{err: &PolicyFailure{Code: "timeout"}},
			{proposal: PolicyProposal{Kind: DecisionNoAction}},
			{proposal: proposal},
		},
	}
	result, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.ReadVerifiedRun(result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	want := []DecisionKind{DecisionPolicyFault, DecisionNoAction, DecisionIntent, DecisionSuppressed}
	got := make([]DecisionKind, len(run.Decisions))
	for i, decision := range run.Decisions {
		got[i] = decision.Kind
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decision kinds = %v, want %v", got, want)
	}
	if run.Decisions[0].FaultCode != "timeout" || run.Decisions[3].SuppressionReason != "actor_action_budget_exhausted" {
		t.Fatalf("fault or suppression not normalized: %#v", run.Decisions)
	}
}

func TestReplayUsesDecisionTraceAndBindsProvenance(t *testing.T) {
	actors := []ActorSpec{engineTestActor("agent-a", "edit"), engineTestActor("agent-b", "edit")}
	proposal := PolicyProposal{Kind: DecisionIntent, Intent: &Intent{Kind: IntentEdit, Path: "src/fix.go", Content: "fixed"}}
	store, engine, spec, _ := engineTestSetup(t, actors, engineTestScenario{completeAt: 2}, proposal)
	source, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	sourceRun, err := store.ReadVerifiedRun(source.RunID)
	if err != nil {
		t.Fatal(err)
	}
	engine.Policies = nil
	replayed, err := engine.Replay(context.Background(), source.RunID, "engine-replay")
	if err != nil {
		t.Fatal(err)
	}
	if replayed.SemanticDigest != source.SemanticDigest {
		t.Fatalf("semantic digest changed: source=%s replay=%s", source.SemanticDigest, replayed.SemanticDigest)
	}
	if replayed.SourceRunID != source.RunID || replayed.SourceSealDigest == "" {
		t.Fatalf("replay result lacks source provenance: %#v", replayed)
	}
	sealBytes, err := json.Marshal(source.Seal)
	if err != nil {
		t.Fatal(err)
	}
	if want := digestBytes(sealBytes); replayed.SourceSealDigest != want {
		t.Fatalf("source seal digest = %s, want %s", replayed.SourceSealDigest, want)
	}
	replayRun, err := store.ReadVerifiedRun(replayed.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if replayRun.Spec.SourceRunID != source.RunID || replayRun.Spec.SourceSealDigest != replayed.SourceSealDigest {
		t.Fatalf("replay spec provenance mismatch: %#v", replayRun.Spec)
	}
	if digest, err := sourceRun.SemanticDigest(); err != nil || digest != replayed.SemanticDigest {
		t.Fatalf("verified source semantic digest = %q, err=%v", digest, err)
	}
}

func TestReplayRejectsMissingScheduledDecision(t *testing.T) {
	actors := []ActorSpec{engineTestActor("agent-a", "edit"), engineTestActor("agent-b", "edit")}
	proposal := PolicyProposal{Kind: DecisionNoAction}
	store, engine, spec, _ := engineTestSetup(t, actors, engineTestScenario{}, proposal)
	writer, err := store.Reserve(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AppendDecision(DecisionRecord{Tick: 1, ActorID: "agent-a", PolicyID: actors[0].Policy.ID, Kind: DecisionNoAction}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Finalize(true); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Replay(context.Background(), spec.RunID, "engine-replay-missing"); !errors.Is(err, ErrDecisionTrace) {
		t.Fatalf("Replay error = %v, want ErrDecisionTrace", err)
	}
}

func TestReplayRejectsUnexpectedScheduledDecision(t *testing.T) {
	actors := []ActorSpec{engineTestActor("agent-a", "edit"), engineTestActor("agent-b", "edit")}
	store, engine, spec, _ := engineTestSetup(t, actors, engineTestScenario{completeAt: 1, skipActor: "agent-b"}, PolicyProposal{Kind: DecisionNoAction})
	writer, err := store.Reserve(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, decision := range []DecisionRecord{
		{Tick: 1, ActorID: "agent-a", PolicyID: actors[0].Policy.ID, Kind: DecisionIntent, Intent: &Intent{Kind: IntentEdit, Path: "src/fix.go", Content: "fixed"}},
		{Tick: 1, ActorID: "agent-b", PolicyID: actors[1].Policy.ID, Kind: DecisionNoAction},
	} {
		if err := writer.AppendDecision(decision); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.Finalize(true); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Replay(context.Background(), spec.RunID, "engine-replay-extra"); !errors.Is(err, ErrDecisionTrace) {
		t.Fatalf("Replay error = %v, want ErrDecisionTrace", err)
	}
}

func TestCanceledPolicyRunRemainsIncomplete(t *testing.T) {
	actor := engineTestActor("agent-a", "edit")
	store, engine, spec, _ := engineTestSetup(t, []ActorSpec{actor}, engineTestScenario{}, PolicyProposal{Kind: DecisionNoAction})
	ctx, cancel := context.WithCancel(context.Background())
	engine.Policies[actor.Policy.ID] = &testPolicy{
		identity: actor.Policy, proposal: PolicyProposal{Kind: DecisionNoAction}, cancel: cancel,
	}
	result, err := engine.Run(ctx, spec)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if _, err := store.Verify(result.RunID); !errors.Is(err, ErrIncompleteRun) {
		t.Fatalf("canceled run verification error = %v, want ErrIncompleteRun", err)
	}
}

func TestReplayRejectsUnsupportedBundleBeforeReserving(t *testing.T) {
	actor := engineTestActor("agent-a", "edit")
	proposal := PolicyProposal{Kind: DecisionNoAction}
	store, engine, spec, _ := engineTestSetup(t, []ActorSpec{actor}, engineTestScenario{}, proposal)
	source, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	engine.Bundle.EngineVersion = "engine-v2"
	if _, err := engine.Replay(context.Background(), source.RunID, "unsupported-replay"); !errors.Is(err, ErrUnsupportedBehaviorBundle) {
		t.Fatalf("Replay error = %v, want ErrUnsupportedBehaviorBundle", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "unsupported-replay")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported replay reserved a run directory: stat error=%v", err)
	}
}

func TestReplayRejectsTamperedSourceBeforeReserving(t *testing.T) {
	actor := engineTestActor("agent-a", "edit")
	store, engine, spec, _ := engineTestSetup(t, []ActorSpec{actor}, engineTestScenario{}, PolicyProposal{Kind: DecisionNoAction})
	source, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.root, string(source.RunID), "public.jsonl")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents = []byte(strings.Replace(string(contents), "no_action", "bad_action", 1))
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Replay(context.Background(), source.RunID, "tampered-replay"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Replay error = %v, want ErrIntegrity", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "tampered-replay")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered replay reserved a run directory: stat error=%v", err)
	}
}
