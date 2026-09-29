package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/benchmark"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/policy"
)

type fixtureList struct {
	SchemaVersion string                        `json:"schema_version"`
	Fixtures      []benchmark.FixtureDefinition `json:"fixtures"`
}

func fixturesCommand(args []string, stdout, stderr io.Writer) error {
	flags := newFlags("fixtures", stderr)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	return writeJSON(stdout, fixtureList{SchemaVersion: "fixture-catalog-v1", Fixtures: benchmark.FixtureCatalog()})
}

type runOutput struct {
	RunID          observatory.RunID    `json:"run_id"`
	ScenarioID     string               `json:"scenario_id"`
	Fixture        benchmark.FixtureID  `json:"fixture"`
	Topology       observatory.Topology `json:"topology"`
	Completed      bool                 `json:"completed"`
	SemanticDigest string               `json:"semantic_digest"`
	Store          string               `json:"store"`
}

func runCommand(args []string, stdout, stderr io.Writer) error {
	flags := newFlags("run", stderr)
	fixtureName := flags.String("fixture", string(benchmark.FixtureHonestCoordination), "registered fixture ID")
	topologyName := flags.String("topology", string(observatory.TopologySharedMessages), "shared_messages or hierarchical")
	workerName := flags.String("worker-policy", string(policy.HonestRepair), "honest_repair, no_action, duplicate_inspector, or reward_gamer")
	storePath := flags.String("store", ".observatory/runs", "run evidence directory")
	repositoryRoot := flags.String("repo", ".", "repository root containing the bundled Python policy")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	task, err := benchmark.NewFixtureTask(benchmark.FixtureID(*fixtureName))
	if err != nil {
		return fmt.Errorf("select fixture %q; use `observatory fixtures` to list valid IDs: %w", *fixtureName, err)
	}
	topology, err := parseTopology(*topologyName)
	if err != nil {
		return err
	}
	root, err := findRepositoryRoot(*repositoryRoot)
	if err != nil {
		return err
	}
	actors, policies, err := pythonPolicies(root, *workerName)
	if err != nil {
		return err
	}
	store, err := openStore(*storePath)
	if err != nil {
		return err
	}
	build, err := buildDigest()
	if err != nil {
		return err
	}
	monitor := observatory.DefaultRuleMonitor()
	environment, err := newRunEnvironment(store, task, topology, actors, policies, monitor, build)
	if err != nil {
		return fmt.Errorf("prepare benchmark run: %w", err)
	}
	result, err := environment.engine.Run(context.Background(), environment.spec)
	if err != nil {
		return fmt.Errorf("run fixture %q: %w", *fixtureName, err)
	}
	return writeJSON(stdout, runOutput{
		RunID: result.RunID, ScenarioID: task.ID, Fixture: benchmark.FixtureID(*fixtureName),
		Topology: topology, Completed: result.Seal.Completed, SemanticDigest: result.SemanticDigest, Store: *storePath,
	})
}

func inspectCommand(args []string, stdout, stderr io.Writer) error {
	flags := newFlags("inspect", stderr)
	storePath := flags.String("store", ".observatory/runs", "run evidence directory")
	runIDValue := flags.String("run-id", "", "run ID")
	limit := flags.Int("limit", 50, "maximum recent records per stream (1-500)")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	if *limit < 1 || *limit > 500 {
		return errors.New("--limit must be between 1 and 500")
	}
	store, err := openStore(*storePath)
	if err != nil {
		return err
	}
	runID, err := observatory.ParseRunID(*runIDValue)
	if err != nil {
		return fmt.Errorf("provide a valid --run-id: %w", err)
	}
	run, err := store.ReadVerifiedRun(runID)
	if err != nil {
		return fmt.Errorf("cannot inspect unverified run %q: %w", runID, err)
	}
	return writeJSON(stdout, struct {
		RunID            observatory.RunID           `json:"run_id"`
		ScenarioID       string                      `json:"scenario_id"`
		Topology         observatory.Topology        `json:"topology"`
		Integrity        string                      `json:"integrity"`
		PublicTotal      uint64                      `json:"public_total"`
		PublicEvents     []observatory.PublicEvent   `json:"public_events"`
		MonitorTotal     uint64                      `json:"monitor_total"`
		MonitorRecords   []observatory.MonitorRecord `json:"monitor_records"`
		RecordsTruncated bool                        `json:"records_truncated"`
	}{
		RunID: runID, ScenarioID: run.Spec.ScenarioID, Topology: run.Spec.Topology, Integrity: "verified",
		PublicTotal: run.Seal.PublicCount, PublicEvents: tailPublic(run.PublicEvents, *limit),
		MonitorTotal: run.Seal.MonitorCount, MonitorRecords: tailMonitor(run.MonitorRecords, *limit),
		RecordsTruncated: len(run.PublicEvents) > *limit || len(run.MonitorRecords) > *limit,
	})
}

func verifyCommand(args []string, stdout, stderr io.Writer) error {
	flags := newFlags("verify", stderr)
	storePath := flags.String("store", ".observatory/runs", "run evidence directory")
	runIDValue := flags.String("run-id", "", "run ID")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	store, err := openStore(*storePath)
	if err != nil {
		return err
	}
	runID, err := observatory.ParseRunID(*runIDValue)
	if err != nil {
		return fmt.Errorf("provide a valid --run-id: %w", err)
	}
	seal, err := store.Verify(runID)
	if err != nil {
		return fmt.Errorf("integrity verification failed for run %q: %w", runID, err)
	}
	return writeJSON(stdout, struct {
		RunID         observatory.RunID `json:"run_id"`
		Verified      bool              `json:"verified"`
		Completed     bool              `json:"completed"`
		PublicCount   uint64            `json:"public_count"`
		TruthCount    uint64            `json:"truth_count"`
		DecisionCount uint64            `json:"decision_count"`
		MonitorCount  uint64            `json:"monitor_count"`
	}{runID, true, seal.Completed, seal.PublicCount, seal.TruthCount, seal.DecisionCount, seal.MonitorCount})
}

func evaluateCommand(args []string, stdout, stderr io.Writer) error {
	flags := newFlags("evaluate", stderr)
	storePath := flags.String("store", ".observatory/runs", "run evidence directory")
	runIDValue := flags.String("run-id", "", "run ID")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	store, err := openStore(*storePath)
	if err != nil {
		return err
	}
	runID, err := observatory.ParseRunID(*runIDValue)
	if err != nil {
		return fmt.Errorf("provide a valid --run-id: %w", err)
	}
	run, err := store.ReadVerifiedRun(runID)
	if err != nil {
		return fmt.Errorf("cannot evaluate unverified run %q: %w", runID, err)
	}
	task, err := taskForScenario(run.Spec.ScenarioID)
	if err != nil {
		return err
	}
	report, err := benchmark.EvaluateRun(store, runID, task)
	if err != nil {
		return fmt.Errorf("evaluate run %q: %w", runID, err)
	}
	return writeJSON(stdout, report)
}

func replayCommand(args []string, stdout, stderr io.Writer) error {
	flags := newFlags("replay", stderr)
	storePath := flags.String("store", ".observatory/runs", "run evidence directory")
	sourceIDValue := flags.String("run-id", "", "verified source run ID")
	replayIDValue := flags.String("replay-id", "", "new replay run ID (generated when omitted)")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	store, err := openStore(*storePath)
	if err != nil {
		return err
	}
	sourceID, err := observatory.ParseRunID(*sourceIDValue)
	if err != nil {
		return fmt.Errorf("provide a valid source --run-id: %w", err)
	}
	source, err := store.ReadVerifiedRun(sourceID)
	if err != nil {
		return fmt.Errorf("refusing to replay unverified source run %q: %w", sourceID, err)
	}
	replayID := observatory.RunID(*replayIDValue)
	if replayID == "" {
		replayID, err = newRunID("replay")
		if err != nil {
			return err
		}
	} else if replayID, err = observatory.ParseRunID(string(replayID)); err != nil {
		return fmt.Errorf("invalid --replay-id: %w", err)
	}
	build, err := buildDigest()
	if err != nil {
		return err
	}
	engine, err := replayEngine(store, source, build)
	if err != nil {
		return err
	}
	result, err := engine.Replay(context.Background(), sourceID, replayID)
	if err != nil {
		return fmt.Errorf("replay failed; no faithful replay was established: %w", err)
	}
	return writeJSON(stdout, struct {
		SourceRunID    observatory.RunID `json:"source_run_id"`
		ReplayRunID    observatory.RunID `json:"replay_run_id"`
		Faithful       bool              `json:"faithful"`
		SemanticDigest string            `json:"semantic_digest"`
	}{sourceID, result.RunID, true, result.SemanticDigest})
}
