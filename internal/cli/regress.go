package cli

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/benchmark"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

//go:embed corpus/v1/incidents.json
var incidentCorpus embed.FS

type incidentManifest struct {
	SchemaVersion string               `json:"schema_version"`
	Incidents     []incidentDefinition `json:"incidents"`
}

type incidentDefinition struct {
	ID             string                 `json:"id"`
	Fixture        benchmark.FixtureID    `json:"fixture"`
	Topology       observatory.Topology   `json:"topology,omitempty"`
	Profile        string                 `json:"profile"`
	MaxStalled     uint64                 `json:"max_stalled_ticks,omitempty"`
	Revocations    []benchmark.Revocation `json:"revocations,omitempty"`
	TamperAfterRun bool                   `json:"tamper_after_run,omitempty"`
	Expected       incidentExpectations   `json:"expected"`
}

type incidentExpectations struct {
	Mergeable             *bool    `json:"mergeable,omitempty"`
	FalsePositive         *bool    `json:"false_positive,omitempty"`
	Detected              *bool    `json:"detected,omitempty"`
	SafeBailouts          *uint64  `json:"safe_bailouts,omitempty"`
	MessagesDelivered     *uint64  `json:"messages_delivered,omitempty"`
	MessagesDropped       *uint64  `json:"messages_dropped,omitempty"`
	ArtifactShares        *uint64  `json:"artifact_shares,omitempty"`
	PermissionRevoked     *bool    `json:"permission_revoked,omitempty"`
	AlertRules            []string `json:"alert_rules,omitempty"`
	AlertActions          []string `json:"alert_actions,omitempty"`
	ContainmentActions    []string `json:"containment_actions,omitempty"`
	ReplayFaithful        *bool    `json:"replay_faithful,omitempty"`
	TamperRejected        *bool    `json:"tamper_rejected,omitempty"`
	InvalidReplayRejected *bool    `json:"invalid_replay_rejected,omitempty"`
}

type regressionActual struct {
	Mergeable             bool     `json:"mergeable"`
	FalsePositive         bool     `json:"false_positive"`
	Detected              bool     `json:"detected"`
	SafeBailouts          uint64   `json:"safe_bailouts"`
	MessagesDelivered     uint64   `json:"messages_delivered"`
	MessagesDropped       uint64   `json:"messages_dropped"`
	ArtifactShares        uint64   `json:"artifact_shares"`
	PermissionRevoked     bool     `json:"permission_revoked"`
	AlertRules            []string `json:"alert_rules"`
	AlertActions          []string `json:"alert_actions"`
	ContainmentActions    []string `json:"containment_actions"`
	ReplayFaithful        bool     `json:"replay_faithful"`
	TamperRejected        bool     `json:"tamper_rejected"`
	InvalidReplayRejected bool     `json:"invalid_replay_rejected"`
}

type regressionCaseResult struct {
	ID       string           `json:"id"`
	Passed   bool             `json:"passed"`
	Actual   regressionActual `json:"actual"`
	Failures []string         `json:"failures,omitempty"`
}

type regressionOutput struct {
	SchemaVersion string                 `json:"schema_version"`
	Passed        bool                   `json:"passed"`
	CaseCount     int                    `json:"case_count"`
	Cases         []regressionCaseResult `json:"cases"`
}

func regressCommand(args []string, stdout, stderr io.Writer) error {
	flags := newFlags("regress", stderr)
	storePath := flags.String("store", "", "persistent run evidence directory (defaults to a temporary directory)")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	temporary := *storePath == ""
	if temporary {
		var err error
		*storePath, err = os.MkdirTemp("", "observatory-regression-")
		if err != nil {
			return fmt.Errorf("create temporary regression store: %w", err)
		}
		defer os.RemoveAll(*storePath)
	}
	store, err := openStore(*storePath)
	if err != nil {
		return err
	}
	build, err := buildDigest()
	if err != nil {
		return err
	}
	manifest, err := loadIncidentManifest()
	if err != nil {
		return err
	}
	result := regressionOutput{SchemaVersion: manifest.SchemaVersion, Passed: true, CaseCount: len(manifest.Incidents), Cases: make([]regressionCaseResult, 0, len(manifest.Incidents))}
	for _, incident := range manifest.Incidents {
		caseResult, caseErr := executeIncident(store, *storePath, build, incident)
		if caseErr != nil {
			caseResult = regressionCaseResult{ID: incident.ID, Passed: false, Failures: []string{caseErr.Error()}}
		}
		result.Cases = append(result.Cases, caseResult)
		if !caseResult.Passed {
			result.Passed = false
		}
	}
	if err := writeJSON(stdout, result); err != nil {
		return err
	}
	if !result.Passed {
		return errors.New("one or more incident regression cases failed; see the JSON failures")
	}
	return nil
}

func loadIncidentManifest() (incidentManifest, error) {
	contents, err := incidentCorpus.ReadFile("corpus/v1/incidents.json")
	if err != nil {
		return incidentManifest{}, fmt.Errorf("read embedded incident corpus: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	var manifest incidentManifest
	if err := decoder.Decode(&manifest); err != nil {
		return incidentManifest{}, fmt.Errorf("decode incident corpus: %w", err)
	}
	if manifest.SchemaVersion != "incident-corpus-v1" || len(manifest.Incidents) == 0 {
		return incidentManifest{}, errors.New("incident corpus has an unsupported schema or no cases")
	}
	seen := make(map[string]bool, len(manifest.Incidents))
	usedFixtures := make(map[benchmark.FixtureID]bool, len(manifest.Incidents))
	for _, incident := range manifest.Incidents {
		if incident.ID == "" || seen[incident.ID] {
			return incidentManifest{}, fmt.Errorf("incident corpus has an empty or duplicate ID %q", incident.ID)
		}
		seen[incident.ID] = true
		if _, err := benchmark.NewFixtureTask(incident.Fixture); err != nil {
			return incidentManifest{}, fmt.Errorf("incident %q references unknown fixture %q", incident.ID, incident.Fixture)
		}
		usedFixtures[incident.Fixture] = true
		if incident.Topology != "" {
			if _, err := parseTopology(string(incident.Topology)); err != nil {
				return incidentManifest{}, fmt.Errorf("incident %q: %w", incident.ID, err)
			}
		}
	}
	for _, fixture := range benchmark.FixtureCatalog() {
		if !usedFixtures[fixture.ID] {
			return incidentManifest{}, fmt.Errorf("incident corpus does not exercise registered fixture %q", fixture.ID)
		}
	}
	return manifest, nil
}

func executeIncident(store *observatory.RunStore, storeRoot, build string, incident incidentDefinition) (regressionCaseResult, error) {
	task, err := benchmark.NewFixtureTask(incident.Fixture)
	if err != nil {
		return regressionCaseResult{}, err
	}
	if incident.MaxStalled > 0 {
		task.MaxStalledTicks = incident.MaxStalled
	}
	task.Revocations = append([]benchmark.Revocation(nil), incident.Revocations...)
	actors, policies, err := demoPolicies(incident.Profile)
	if err != nil {
		return regressionCaseResult{}, err
	}
	topology := incident.Topology
	if topology == "" {
		topology = observatory.TopologySharedMessages
	}
	monitor := observatory.DefaultRuleMonitor()
	environment, err := newRunEnvironment(store, task, topology, actors, policies, monitor, build)
	if err != nil {
		return regressionCaseResult{}, fmt.Errorf("prepare incident %q: %w", incident.ID, err)
	}
	runResult, err := environment.engine.Run(context.Background(), environment.spec)
	if err != nil {
		return regressionCaseResult{}, fmt.Errorf("run incident %q: %w", incident.ID, err)
	}
	verified, err := store.ReadVerifiedRun(runResult.RunID)
	if err != nil {
		return regressionCaseResult{}, fmt.Errorf("verify incident %q: %w", incident.ID, err)
	}
	actual := regressionActual{AlertRules: []string{}, AlertActions: []string{}, ContainmentActions: []string{}}
	if incident.TamperAfterRun {
		if err := corruptPublicStream(storeRoot, runResult.RunID); err != nil {
			return regressionCaseResult{}, err
		}
		_, verifyErr := store.Verify(runResult.RunID)
		actual.TamperRejected = errors.Is(verifyErr, observatory.ErrIntegrity)
		replayID, err := newRunID("replay")
		if err != nil {
			return regressionCaseResult{}, err
		}
		_, replayErr := environment.engine.Replay(context.Background(), runResult.RunID, replayID)
		actual.InvalidReplayRejected = errors.Is(replayErr, observatory.ErrIntegrity)
	} else {
		report, err := benchmark.EvaluateRun(store, runResult.RunID, task)
		if err != nil {
			return regressionCaseResult{}, fmt.Errorf("score incident %q: %w", incident.ID, err)
		}
		actual.Mergeable = report.Metrics.TaskQuality.Mergeable
		actual.FalsePositive = report.Metrics.Monitor.FalsePositiveRun
		actual.Detected = report.Metrics.Monitor.Detection.Detected
		actual.SafeBailouts = report.Metrics.Abstention.SafeBailouts
		actual.MessagesDelivered = report.Metrics.Coordination.MessagesDelivered
		actual.MessagesDropped = report.Metrics.Coordination.MessagesDropped
		actual.ArtifactShares = report.Metrics.Coordination.ArtifactShares
		for _, event := range verified.PublicEvents {
			if event.ReasonCode == "permission_revoked" {
				actual.PermissionRevoked = true
			}
		}
		collectMonitorActions(&actual, verified.MonitorRecords)
		replayID, err := newRunID("replay")
		if err != nil {
			return regressionCaseResult{}, err
		}
		replay, err := environment.engine.Replay(context.Background(), runResult.RunID, replayID)
		if err != nil {
			return regressionCaseResult{}, fmt.Errorf("replay incident %q: %w", incident.ID, err)
		}
		actual.ReplayFaithful = replay.SemanticDigest == runResult.SemanticDigest
	}
	sort.Strings(actual.AlertRules)
	sort.Strings(actual.AlertActions)
	sort.Strings(actual.ContainmentActions)
	caseResult := regressionCaseResult{ID: incident.ID, Actual: actual}
	caseResult.Failures = compareExpectations(incident.Expected, actual)
	caseResult.Passed = len(caseResult.Failures) == 0
	return caseResult, nil
}

func collectMonitorActions(actual *regressionActual, records []observatory.MonitorRecord) {
	rules := make(map[string]bool)
	for _, record := range records {
		if record.Action == nil {
			continue
		}
		switch record.Kind {
		case observatory.MonitorRecordAlert:
			if record.Outcome == "scheduled" {
				rules[record.RuleID] = true
				actual.AlertActions = append(actual.AlertActions, actionName(*record.Action))
			}
		case observatory.MonitorRecordApplied:
			actual.ContainmentActions = append(actual.ContainmentActions, actionName(*record.Action))
		}
	}
	for rule := range rules {
		actual.AlertRules = append(actual.AlertRules, rule)
	}
}

func actionName(action observatory.ContainmentAction) string {
	if action.Kind == observatory.ContainmentRevokeCapability {
		return string(action.Kind) + ":" + string(action.Capability)
	}
	return string(action.Kind)
}

func compareExpectations(expected incidentExpectations, actual regressionActual) []string {
	failures := make([]string, 0)
	checkBool := func(name string, want *bool, got bool) {
		if want != nil && *want != got {
			failures = append(failures, fmt.Sprintf("%s: want %t, got %t", name, *want, got))
		}
	}
	checkUint := func(name string, want *uint64, got uint64) {
		if want != nil && *want != got {
			failures = append(failures, fmt.Sprintf("%s: want %d, got %d", name, *want, got))
		}
	}
	checkSlice := func(name string, want, got []string) {
		if want == nil {
			return
		}
		wantSorted, gotSorted := append([]string(nil), want...), append([]string(nil), got...)
		sort.Strings(wantSorted)
		sort.Strings(gotSorted)
		if strings.Join(wantSorted, "\x00") != strings.Join(gotSorted, "\x00") {
			failures = append(failures, fmt.Sprintf("%s: want %v, got %v", name, wantSorted, gotSorted))
		}
	}
	checkBool("mergeable", expected.Mergeable, actual.Mergeable)
	checkBool("false_positive", expected.FalsePositive, actual.FalsePositive)
	checkBool("detected", expected.Detected, actual.Detected)
	checkUint("safe_bailouts", expected.SafeBailouts, actual.SafeBailouts)
	checkUint("messages_delivered", expected.MessagesDelivered, actual.MessagesDelivered)
	checkUint("messages_dropped", expected.MessagesDropped, actual.MessagesDropped)
	checkUint("artifact_shares", expected.ArtifactShares, actual.ArtifactShares)
	checkBool("permission_revoked", expected.PermissionRevoked, actual.PermissionRevoked)
	checkSlice("alert_rules", expected.AlertRules, actual.AlertRules)
	checkSlice("alert_actions", expected.AlertActions, actual.AlertActions)
	checkSlice("containment_actions", expected.ContainmentActions, actual.ContainmentActions)
	checkBool("replay_faithful", expected.ReplayFaithful, actual.ReplayFaithful)
	checkBool("tamper_rejected", expected.TamperRejected, actual.TamperRejected)
	checkBool("invalid_replay_rejected", expected.InvalidReplayRejected, actual.InvalidReplayRejected)
	return failures
}

func corruptPublicStream(storeRoot string, runID observatory.RunID) error {
	root, err := filepath.Abs(storeRoot)
	if err != nil {
		return err
	}
	path := filepath.Join(root, string(runID), "public.jsonl")
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read run stream for tamper incident: %w", err)
	}
	if len(contents) == 0 {
		return errors.New("tamper incident produced an empty public stream")
	}
	contents[0] = '['
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		return fmt.Errorf("tamper run stream: %w", err)
	}
	return nil
}
