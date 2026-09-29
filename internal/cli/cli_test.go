package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/benchmark"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

func TestIncidentCorpusRegression(t *testing.T) {
	store := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"regress", "--store", store}, &stdout, &stderr); err != nil {
		t.Fatalf("regress: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}
	var report regressionOutput
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode regression report: %v", err)
	}
	if !report.Passed || report.CaseCount != 9 || len(report.Cases) != report.CaseCount {
		t.Fatalf("unexpected regression report: %#v", report)
	}
	for _, testCase := range report.Cases {
		if !testCase.Passed {
			t.Errorf("incident %s failed: %v", testCase.ID, testCase.Failures)
		}
	}
}

func TestCLICommandsRunVerifyInspectEvaluateAndReplay(t *testing.T) {
	store := t.TempDir()
	root := repositoryRoot(t)
	var runOutputBuffer, stderr bytes.Buffer
	if err := Run([]string{
		"run", "--fixture", "honest-coordination", "--topology", "hierarchical",
		"--worker-policy", "honest_repair", "--store", store, "--repo", root,
	}, &runOutputBuffer, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	var run runOutput
	if err := json.Unmarshal(runOutputBuffer.Bytes(), &run); err != nil {
		t.Fatalf("decode run output: %v", err)
	}
	if !run.Completed || run.Topology != observatory.TopologyHierarchical || run.RunID == "" {
		t.Fatalf("unexpected run output: %#v", run)
	}
	commands := [][]string{
		{"verify", "--store", store, "--run-id", string(run.RunID)},
		{"inspect", "--store", store, "--run-id", string(run.RunID), "--limit", "1"},
		{"evaluate", "--store", store, "--run-id", string(run.RunID)},
		{"replay", "--store", store, "--run-id", string(run.RunID), "--replay-id", "test-replay"},
	}
	for _, args := range commands {
		stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
		if err := Run(args, stdout, stderr); err != nil {
			t.Errorf("%s: %v\nstderr: %s", args[0], err, stderr.String())
			continue
		}
		if !json.Valid(stdout.Bytes()) {
			t.Errorf("%s emitted invalid JSON: %s", args[0], stdout.String())
			continue
		}
		switch args[0] {
		case "verify":
			var result struct {
				Verified bool `json:"verified"`
			}
			_ = json.Unmarshal(stdout.Bytes(), &result)
			if !result.Verified {
				t.Error("verify did not report a verified run")
			}
		case "inspect":
			var result struct {
				Integrity        string `json:"integrity"`
				RecordsTruncated bool   `json:"records_truncated"`
			}
			_ = json.Unmarshal(stdout.Bytes(), &result)
			if result.Integrity != "verified" || !result.RecordsTruncated {
				t.Errorf("inspect did not return a bounded verified trace: %#v", result)
			}
		case "evaluate":
			var result benchmark.EvaluationReport
			_ = json.Unmarshal(stdout.Bytes(), &result)
			if !result.Metrics.TaskQuality.Mergeable || !result.EvidenceIntegrity.Verified {
				t.Errorf("evaluate did not score the verified repair: %#v", result)
			}
		case "replay":
			var result struct {
				Faithful bool `json:"faithful"`
			}
			_ = json.Unmarshal(stdout.Bytes(), &result)
			if !result.Faithful {
				t.Error("replay did not establish semantic fidelity")
			}
		}
	}
}

func TestCLIRejectsUnknownFixtureAndUnsupportedReplayBundle(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"run", "--fixture", "missing-fixture"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "observatory fixtures") {
		t.Fatalf("unknown fixture error = %v", err)
	}
	build, err := buildDigest()
	if err != nil {
		t.Fatal(err)
	}
	store, err := observatory.NewRunStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := observatory.VerifiedRun{Spec: observatory.RunSpec{BehaviorBundle: observatory.BehaviorBundle{EngineVersion: "old-engine"}}}
	if _, err := replayEngine(store, source, build); err == nil || !strings.Contains(err.Error(), "unsupported behavior bundle") {
		t.Fatalf("unsupported bundle error = %v", err)
	}
}

func TestCommandHelpDoesNotStartRun(t *testing.T) {
	store := filepath.Join(t.TempDir(), "must-not-exist")
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"run", "--help", "--store", store}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("help invocation touched run store: %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate CLI test source")
	}
	root, err := findRepositoryRoot(filepath.Dir(file))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
