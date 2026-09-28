package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/benchmark"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func policyFixture(t *testing.T, workerPolicy Name, workerLimits Limits, removeEdit bool, workerBudget uint64) (*observatory.Engine[benchmark.WorldState], observatory.RunSpec, observatory.AgentObservation) {
	t.Helper()
	actors := benchmark.DefaultActorSpecs()
	task, err := benchmark.NewFixtureTask(benchmark.FixtureHonestCoordination)
	if err != nil {
		t.Fatal(err)
	}
	policies := make(map[observatory.PolicyID]observatory.DecisionPolicy)
	for index := range actors {
		name := NoAction
		limits := Limits{}
		if actors[index].ID == "agent-worker" {
			name = workerPolicy
			limits = workerLimits
			if workerBudget > 0 {
				actors[index].ActionBudget = workerBudget
			}
			if removeEdit {
				capabilities := actors[index].Capabilities[:0]
				for _, capability := range actors[index].Capabilities {
					if capability != "edit" {
						capabilities = append(capabilities, capability)
					}
				}
				actors[index].Capabilities = capabilities
			}
		}
		policy, err := NewBundledPython(repositoryRoot(t), name, limits)
		if err != nil {
			t.Fatal(err)
		}
		actors[index].Policy = policy.Identity()
		policies[policy.Identity().ID] = policy
	}
	base := observatory.RunSpec{
		RunID: "python-run", ScenarioID: task.ID,
		Topology: observatory.TopologySharedMessages, Seed: 17,
		BehaviorBundle: observatory.BehaviorBundle{
			EngineVersion: "engine-v1", MonitorVersion: "monitor-v1", ContainmentVersion: "containment-v1",
			EvaluatorVersion: "evaluator-v1", PolicyProtocolVersion: "policy-v1", BuildDigest: strings.Repeat("a", 64),
		},
		ProtocolVersion: 1, Actors: actors,
		Limits: observatory.RunLimits{MaxTicks: 8, MaxTotalActions: 64, MaxTotalSpend: 100, MaxOutputBytes: 4096},
	}
	pair, err := benchmark.NewPairedBenchmark(task, base)
	if err != nil {
		t.Fatal(err)
	}
	store, err := observatory.NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	engine := &observatory.Engine[benchmark.WorldState]{
		Store: store, Bundle: pair.SharedSpec.BehaviorBundle,
		Scenario: pair.SharedScenario, Policies: policies,
	}
	state := pair.SharedScenario.InitialState(pair.SharedSpec.Seed)
	worker := actorSpec(pair.SharedSpec.Actors, "agent-worker")
	data, err := pair.SharedScenario.Observe(state, worker, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation := observatory.AgentObservation{
		ScenarioID: pair.SharedSpec.ScenarioID, Tick: 1, ActorID: worker.ID,
		Capabilities:          pair.SharedScenario.AvailableCapabilities(state, worker, 1),
		RemainingActionBudget: worker.ActionBudget, Data: data,
	}
	return engine, pair.SharedSpec, observation
}

func actorSpec(actors []observatory.ActorSpec, id observatory.ActorID) observatory.ActorSpec {
	for _, actor := range actors {
		if actor.ID == id {
			return actor
		}
	}
	return observatory.ActorSpec{}
}

func policyFailureCode(t *testing.T, err error) string {
	t.Helper()
	var failure observatory.PolicyFailure
	if !errors.As(err, &failure) {
		t.Fatalf("error %v is not a normalized policy failure", err)
	}
	return failure.Code
}

func TestBundledPoliciesReturnTypedProposals(t *testing.T) {
	_, _, observation := policyFixture(t, HonestRepair, Limits{}, false, 0)
	honest, err := NewBundledPython(repositoryRoot(t), HonestRepair, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := honest.Decide(context.Background(), observation)
	if err != nil {
		source, _ := os.ReadFile(honest.scriptPath)
		request, _ := json.Marshal(policyRequest{
			ProtocolVersion: protocolVersion, ScenarioID: observation.ScenarioID, Tick: observation.Tick,
			ActorID: observation.ActorID, Capabilities: observation.Capabilities,
			RemainingActionBudget: observation.RemainingActionBudget, Observation: observation.Data,
		})
		_, rawErr := runBounded(context.Background(), honest.executable, string(source), honest.name, append(request, '\n'), honest.limits)
		t.Fatalf("honest policy decision: %v (raw runner error: %v)", err, rawErr)
	}
	if proposal.Kind != observatory.DecisionIntent || proposal.Intent == nil || proposal.Intent.Kind != observatory.IntentInspect || proposal.Intent.Path != "src/parser.go" {
		t.Fatalf("honest policy first action = %#v", proposal)
	}
	noAction, err := NewBundledPython(repositoryRoot(t), NoAction, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	proposal, err = noAction.Decide(context.Background(), observation)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Kind != observatory.DecisionNoAction || proposal.Intent != nil {
		t.Fatalf("no-action policy proposal = %#v", proposal)
	}
}

func TestBundledPolicyFaultsAreNormalized(t *testing.T) {
	_, _, observation := policyFixture(t, NoAction, Limits{}, false, 0)
	cases := []struct {
		name Name
		want string
	}{
		{WrongVersionProbe, "protocol_version_mismatch"},
		{MalformedOutputProbe, "malformed_response"},
		{OversizedOutputProbe, "output_limit"},
		{StderrProbe, "stderr_limit"},
		{TimeoutProbe, "timeout"},
		{UnknownActionProbe, "invalid_policy_response"},
	}
	for _, test := range cases {
		t.Run(string(test.name), func(t *testing.T) {
			limits := DefaultLimits()
			if test.name == TimeoutProbe {
				limits.Timeout = 250 * time.Millisecond
			}
			policy, err := NewBundledPython(repositoryRoot(t), test.name, limits)
			if err != nil {
				t.Fatal(err)
			}
			_, err = policy.Decide(context.Background(), observation)
			if got := policyFailureCode(t, err); got != test.want {
				t.Fatalf("failure code = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInputBudgetIdentityAndTruthBoundary(t *testing.T) {
	_, _, observation := policyFixture(t, NoAction, Limits{}, false, 0)
	limits := DefaultLimits()
	limits.InputBytes = 32
	policy, err := NewBundledPython(repositoryRoot(t), NoAction, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Decide(context.Background(), observation); policyFailureCode(t, err) != "input_limit" {
		t.Fatal("oversized policy request was not rejected")
	}

	policy, err = NewBundledPython(repositoryRoot(t), NoAction, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	invalidActor := observation
	invalidActor.ActorID = "../invalid"
	if _, err := policy.Decide(context.Background(), invalidActor); policyFailureCode(t, err) != "invalid_identity" {
		t.Fatal("invalid actor identity was not rejected")
	}
	noBudget := observation
	noBudget.RemainingActionBudget = 0
	if _, err := policy.Decide(context.Background(), noBudget); policyFailureCode(t, err) != "action_budget_exhausted" {
		t.Fatal("exhausted actor action budget was not rejected")
	}

	var data map[string]any
	if err := json.Unmarshal(observation.Data, &data); err != nil {
		t.Fatal(err)
	}
	if _, exists := data["expected_digest"]; exists {
		t.Fatal("scenario observation contains an evaluator-only truth field")
	}
	data["expected_digest"] = "TRUTH_ONLY_SENTINEL"
	observation.Data, err = json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Decide(context.Background(), observation); policyFailureCode(t, err) != "unknown_observation_field" || strings.Contains(err.Error(), "TRUTH_ONLY_SENTINEL") {
		t.Fatal("truth-bearing observation field was not rejected")
	}
	if _, err := NewBundledPython(repositoryRoot(t), Name("user_plugin"), Limits{}); err == nil {
		t.Fatal("arbitrary policy plugin was accepted")
	}
}

func TestMalformedJSONRequestIsRejectedByPythonRunner(t *testing.T) {
	script, err := os.ReadFile(filepath.Join(repositoryRoot(t), "python", "observatory_policies", "runner.py"))
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "malformed", input: "{not-json}\n", want: "malformed_json"},
		{name: "duplicate_key", input: `{"protocol_version":1,"protocol_version":1}` + "\n", want: "malformed_json"},
		{name: "oversized", input: strings.Repeat("x", (1<<20)+1) + "\n", want: "input_too_large"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(python, "-I", "-S", "-B", "-c", string(script), string(NoAction))
			command.Dir = t.TempDir()
			command.Stdin = strings.NewReader(test.input)
			output, err := command.Output()
			if err != nil {
				t.Fatalf("runner response: %v", err)
			}
			if !bytes.Contains(output, []byte(`"error":"`+test.want+`"`)) {
				t.Fatalf("response = %s, want error %q", output, test.want)
			}
		})
	}
}

func TestBundledPoliciesRunAndReplayVerifiedRepair(t *testing.T) {
	engine, spec, _ := policyFixture(t, HonestRepair, Limits{}, false, 0)
	result, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := engine.Store.ReadVerifiedRun(result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	verified, submitted := false, false
	for _, event := range run.PublicEvents {
		verified = verified || event.Kind == "verification" && event.Outcome == "passed"
		submitted = submitted || event.Kind == "submission" && event.Outcome == "accepted"
	}
	if !verified || !submitted || len(run.TruthRecords) != 1 || !run.TruthRecords[0].Value {
		t.Fatalf("bundled policy did not complete a verified repair: verified=%v submitted=%v truth=%#v", verified, submitted, run.TruthRecords)
	}
	engine.Policies = nil
	replayed, err := engine.Replay(context.Background(), result.RunID, "python-replay")
	if err != nil {
		t.Fatal(err)
	}
	if replayed.SemanticDigest != result.SemanticDigest {
		t.Fatalf("replay digest = %s, want %s", replayed.SemanticDigest, result.SemanticDigest)
	}
}

func TestGoEngineRejectsUnauthorizedProposalAndEnforcesBudget(t *testing.T) {
	engine, spec, _ := policyFixture(t, UnauthorizedEditProbe, Limits{}, true, 1)
	result, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err := engine.Store.ReadVerifiedRun(result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	denied, acceptedEdit := false, false
	budgetSuppressed := false
	for _, event := range run.PublicEvents {
		denied = denied || event.Kind == "intent_rejected" && event.ReasonCode == "capability_denied"
		acceptedEdit = acceptedEdit || event.Kind == "tool_attempt" && event.IntentKind == observatory.IntentEdit && event.Outcome == "accepted"
	}
	for _, decision := range run.Decisions {
		budgetSuppressed = budgetSuppressed || decision.ActorID == "agent-worker" && decision.SuppressionReason == "actor_action_budget_exhausted"
	}
	if !denied || acceptedEdit || !budgetSuppressed {
		t.Fatalf("Go enforcement mismatch: denied=%v acceptedEdit=%v budgetSuppressed=%v", denied, acceptedEdit, budgetSuppressed)
	}
	engine.Policies = nil
	if _, err := engine.Replay(context.Background(), result.RunID, "python-capability-replay"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyFaultDecisionsReplayWithoutRerunningPython(t *testing.T) {
	for _, test := range []struct {
		name     Name
		want     string
		timeout  time.Duration
		replayID observatory.RunID
	}{
		{name: WrongVersionProbe, want: "protocol_version_mismatch", replayID: "python-protocol-fault-replay"},
		{name: TimeoutProbe, want: "timeout", timeout: 250 * time.Millisecond, replayID: "python-timeout-fault-replay"},
	} {
		t.Run(string(test.name), func(t *testing.T) {
			limits := Limits{}
			if test.timeout > 0 {
				limits = DefaultLimits()
				limits.Timeout = test.timeout
			}
			engine, spec, _ := policyFixture(t, test.name, limits, false, 0)
			result, err := engine.Run(context.Background(), spec)
			if err != nil {
				t.Fatal(err)
			}
			run, err := engine.Store.ReadVerifiedRun(result.RunID)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, decision := range run.Decisions {
				found = found || decision.ActorID == "agent-worker" && decision.Kind == observatory.DecisionPolicyFault && decision.FaultCode == test.want
			}
			if !found {
				t.Fatalf("%s failure was not recorded as a normalized decision", test.want)
			}
			engine.Policies = nil
			replayed, err := engine.Replay(context.Background(), result.RunID, test.replayID)
			if err != nil {
				t.Fatal(err)
			}
			if replayed.SemanticDigest != result.SemanticDigest {
				t.Fatalf("fault replay digest = %s, want %s", replayed.SemanticDigest, result.SemanticDigest)
			}
		})
	}
}
