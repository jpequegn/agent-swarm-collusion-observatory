package benchmark

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

const (
	maxFixtureFiles        = 32
	maxFixtureFileBytes    = 8 << 10
	maxFixtureRepoBytes    = 256 << 10
	maxFixtureArtifact     = 1 << 10
	maxFixtureArtifacts    = 64
	maxFixtureMessages     = 64
	maxFixtureMessageBytes = 128
	maxFixtureActors       = 64
	maxFixtureTicks        = 100
	maxFixtureActions      = 1000
	maxFixtureOutputBytes  = 64 << 20
)

type RewardRule string

const (
	RewardVerifiedRepair RewardRule = "verified_repair"
	RewardEditActivity   RewardRule = "edit_activity"
)

type Artifact struct {
	ID      string              `json:"id"`
	Owner   observatory.ActorID `json:"owner"`
	Content string              `json:"content"`
}

type Revocation struct {
	AtTick     uint64                 `json:"at_tick"`
	ActorID    observatory.ActorID    `json:"actor_id"`
	Capability observatory.Capability `json:"capability"`
}

type VerificationCase struct {
	Input string `json:"input"`
	Want  bool   `json:"want"`
}

type Task struct {
	ID                string                                      `json:"id"`
	InitialFiles      map[string]string                           `json:"initial_files"`
	ExpectedFiles     map[string]string                           `json:"expected_files"`
	VerificationFile  string                                      `json:"verification_file"`
	VerificationCases []VerificationCase                          `json:"verification_cases"`
	AllowedPaths      []string                                    `json:"allowed_paths"`
	ReadAccess        map[observatory.ActorID][]string            `json:"read_access"`
	EditAccess        map[observatory.ActorID][]string            `json:"edit_access"`
	ReportsTo         map[observatory.ActorID]observatory.ActorID `json:"reports_to"`
	Artifacts         []Artifact                                  `json:"artifacts,omitempty"`
	Revocations       []Revocation                                `json:"revocations,omitempty"`
	ToolCosts         map[observatory.IntentKind]uint64           `json:"tool_costs,omitempty"`
	RewardRule        RewardRule                                  `json:"reward_rule"`
	DropMessages      bool                                        `json:"drop_messages,omitempty"`
	MaxStalledTicks   uint64                                      `json:"max_stalled_ticks,omitempty"`
}

type PairedBenchmark struct {
	SharedSpec           observatory.RunSpec
	HierarchicalSpec     observatory.RunSpec
	SharedScenario       *PackageRepairScenario
	HierarchicalScenario *PackageRepairScenario
}

type PackageRepairScenario struct {
	task      Task
	topology  observatory.Topology
	actors    map[observatory.ActorID]observatory.ActorSpec
	limits    observatory.RunLimits
	artifacts map[string]Artifact
	revoked   map[observatory.ActorID]map[observatory.Capability][]uint64
	readable  map[observatory.ActorID]map[string]bool
	editable  map[observatory.ActorID]map[string]bool
}

// NewPairedBenchmark creates two otherwise identical run specs and matching
// scenarios. Only run identity and topology differ between the pair.
func NewPairedBenchmark(task Task, base observatory.RunSpec) (PairedBenchmark, error) {
	if base.SourceRunID != "" || base.SourceSealDigest != "" {
		return PairedBenchmark{}, errors.New("benchmark base spec cannot carry replay provenance")
	}
	if base.ScenarioID != task.ID {
		return PairedBenchmark{}, fmt.Errorf("scenario ID %q does not match task ID %q", base.ScenarioID, task.ID)
	}
	if len(base.Actors) == 0 || len(base.Actors) > maxFixtureActors || base.Limits.MaxTicks > maxFixtureTicks || uint64(len(base.Actors))*base.Limits.MaxTicks > 5000 || base.Limits.MaxTotalActions > maxFixtureActions || base.Limits.MaxOutputBytes > maxFixtureOutputBytes {
		return PairedBenchmark{}, errors.New("benchmark limits exceed the offline fixture bounds")
	}
	if base.Limits.MaxTotalSpend == 0 || base.Limits.MaxTotalSpend > 1_000_000 {
		return PairedBenchmark{}, errors.New("benchmark requires a positive bounded total spend limit")
	}
	base.Topology = observatory.TopologySharedMessages
	if err := base.Validate(); err != nil {
		return PairedBenchmark{}, fmt.Errorf("validate benchmark run spec: %w", err)
	}
	if err := task.validate(base.Actors, base.Limits); err != nil {
		return PairedBenchmark{}, err
	}

	shared := cloneRunSpec(base)
	shared.RunID = observatory.RunID(string(base.RunID) + "-shared")
	shared.Topology = observatory.TopologySharedMessages
	hierarchical := cloneRunSpec(base)
	hierarchical.RunID = observatory.RunID(string(base.RunID) + "-hierarchical")
	hierarchical.Topology = observatory.TopologyHierarchical
	if err := shared.Validate(); err != nil {
		return PairedBenchmark{}, fmt.Errorf("validate shared-topology spec: %w", err)
	}
	if err := hierarchical.Validate(); err != nil {
		return PairedBenchmark{}, fmt.Errorf("validate hierarchical-topology spec: %w", err)
	}
	sharedScenario, err := newScenario(task, shared.Topology, shared.Actors, shared.Limits)
	if err != nil {
		return PairedBenchmark{}, err
	}
	hierarchicalScenario, err := newScenario(task, hierarchical.Topology, hierarchical.Actors, hierarchical.Limits)
	if err != nil {
		return PairedBenchmark{}, err
	}
	return PairedBenchmark{
		SharedSpec: shared, HierarchicalSpec: hierarchical,
		SharedScenario: sharedScenario, HierarchicalScenario: hierarchicalScenario,
	}, nil
}

func (t Task) validate(actors []observatory.ActorSpec, limits observatory.RunLimits) error {
	if !validTaskID(t.ID) || len(t.InitialFiles) == 0 || len(t.ExpectedFiles) == 0 || len(t.InitialFiles)+len(t.ExpectedFiles) > maxFixtureFiles || len(t.AllowedPaths) > maxFixtureFiles || len(t.Artifacts) > maxFixtureArtifacts || len(t.Revocations) > maxFixtureActors*64 || len(t.VerificationCases) == 0 || len(t.VerificationCases) > 16 || t.RewardRule != RewardVerifiedRepair && t.RewardRule != RewardEditActivity {
		return errors.New("invalid package-repair task definition")
	}
	if t.MaxStalledTicks > limits.MaxTicks {
		return errors.New("stall limit cannot exceed the run tick limit")
	}
	actorSet := make(map[observatory.ActorID]bool, len(actors))
	actorCapabilities := make(map[observatory.ActorID]map[observatory.Capability]bool, len(actors))
	for _, actor := range actors {
		actorSet[actor.ID] = true
		actorCapabilities[actor.ID] = make(map[observatory.Capability]bool, len(actor.Capabilities))
		for _, capability := range actor.Capabilities {
			actorCapabilities[actor.ID][capability] = true
		}
	}
	allowed := make(map[string]bool, len(t.AllowedPaths))
	for _, filePath := range t.AllowedPaths {
		if !validFixturePath(filePath) || allowed[filePath] {
			return fmt.Errorf("invalid or duplicate allowed path %q", filePath)
		}
		allowed[filePath] = true
	}
	if len(allowed) == 0 {
		return errors.New("task has no allowed file paths")
	}
	for label, files := range map[string]map[string]string{"initial": t.InitialFiles, "expected": t.ExpectedFiles} {
		repositoryBytes := 0
		for filePath, content := range files {
			if !allowed[filePath] || len(content) > maxFixtureFileBytes || !utf8.ValidString(content) {
				return fmt.Errorf("invalid %s fixture file %q", label, filePath)
			}
			repositoryBytes += len(content)
		}
		if repositoryBytes > maxFixtureRepoBytes {
			return fmt.Errorf("%s fixture repository exceeds the byte limit", label)
		}
	}
	if len(t.InitialFiles) != len(t.ExpectedFiles) {
		return errors.New("initial and expected repositories must have identical path sets")
	}
	for filePath := range t.InitialFiles {
		if _, exists := t.ExpectedFiles[filePath]; !exists {
			return fmt.Errorf("expected repository is missing path %q", filePath)
		}
	}
	if !allowed[t.VerificationFile] {
		return errors.New("verification file is outside the finite repository")
	}
	seenInputs := make(map[string]bool, len(t.VerificationCases))
	for _, testCase := range t.VerificationCases {
		if !utf8.ValidString(testCase.Input) || len(testCase.Input) > 1024 || seenInputs[testCase.Input] {
			return errors.New("invalid or duplicate verification input")
		}
		seenInputs[testCase.Input] = true
	}
	if parsed, results := evaluateFunction(t.ExpectedFiles[t.VerificationFile], t.VerificationCases); !parsed || !matchesCases(results, t.VerificationCases) {
		return errors.New("expected fixture does not satisfy its fixed verifier")
	}
	for _, access := range []map[observatory.ActorID][]string{t.ReadAccess, t.EditAccess} {
		for actor, paths := range access {
			if !actorSet[actor] {
				return fmt.Errorf("file access references unknown actor %q", actor)
			}
			seen := make(map[string]bool, len(paths))
			for _, filePath := range paths {
				if !allowed[filePath] || seen[filePath] {
					return fmt.Errorf("invalid or duplicate path access %q for actor %q", filePath, actor)
				}
				if _, exists := t.InitialFiles[filePath]; !exists {
					return fmt.Errorf("path access references missing fixture file %q", filePath)
				}
				seen[filePath] = true
			}
		}
	}
	for actor, manager := range t.ReportsTo {
		if !actorSet[actor] || !actorSet[manager] || actor == manager {
			return fmt.Errorf("invalid reporting relationship %q -> %q", actor, manager)
		}
		seen := map[observatory.ActorID]bool{actor: true}
		for current := manager; current != ""; current = t.ReportsTo[current] {
			if seen[current] {
				return errors.New("reporting hierarchy contains a cycle")
			}
			seen[current] = true
		}
	}
	artifactIDs := make(map[string]bool, len(t.Artifacts))
	for _, artifact := range t.Artifacts {
		if !validTaskID(artifact.ID) || !actorSet[artifact.Owner] || len(artifact.Content) > maxFixtureArtifact || !utf8.ValidString(artifact.Content) || artifactIDs[artifact.ID] {
			return fmt.Errorf("invalid or duplicate fixture artifact %q", artifact.ID)
		}
		artifactIDs[artifact.ID] = true
	}
	for _, revocation := range t.Revocations {
		if revocation.AtTick == 0 || revocation.AtTick > limits.MaxTicks || !actorSet[revocation.ActorID] || !actorCapabilities[revocation.ActorID][revocation.Capability] {
			return errors.New("invalid capability revocation schedule")
		}
	}
	for kind, cost := range t.ToolCosts {
		if !validIntentKind(kind) || cost == 0 {
			return errors.New("fixture tool costs must have valid actions and positive amounts")
		}
	}
	return nil
}

func newScenario(task Task, topology observatory.Topology, actorSpecs []observatory.ActorSpec, limits observatory.RunLimits) (*PackageRepairScenario, error) {
	if topology != observatory.TopologySharedMessages && topology != observatory.TopologyHierarchical {
		return nil, errors.New("unsupported benchmark topology")
	}
	scenario := &PackageRepairScenario{
		task: cloneTask(task), topology: topology, limits: limits,
		actors:    make(map[observatory.ActorID]observatory.ActorSpec, len(actorSpecs)),
		artifacts: make(map[string]Artifact, len(task.Artifacts)),
		revoked:   make(map[observatory.ActorID]map[observatory.Capability][]uint64),
		readable:  make(map[observatory.ActorID]map[string]bool),
		editable:  make(map[observatory.ActorID]map[string]bool),
	}
	for _, actor := range actorSpecs {
		scenario.actors[actor.ID] = actor
	}
	for actor, paths := range task.ReadAccess {
		scenario.readable[actor] = stringSet(paths)
	}
	for actor, paths := range task.EditAccess {
		scenario.editable[actor] = stringSet(paths)
	}
	for _, artifact := range task.Artifacts {
		scenario.artifacts[artifact.ID] = artifact
	}
	for _, revocation := range task.Revocations {
		if scenario.revoked[revocation.ActorID] == nil {
			scenario.revoked[revocation.ActorID] = make(map[observatory.Capability][]uint64)
		}
		scenario.revoked[revocation.ActorID][revocation.Capability] = append(scenario.revoked[revocation.ActorID][revocation.Capability], revocation.AtTick)
	}
	return scenario, nil
}

func (s *PackageRepairScenario) ID() string { return s.task.ID }

func (s *PackageRepairScenario) Topology() observatory.Topology { return s.topology }

func (s *PackageRepairScenario) AvailableCapabilities(state WorldState, actor observatory.ActorSpec, tick uint64) []observatory.Capability {
	return s.effectiveCapabilities(state, actor, tick)
}

func (s *PackageRepairScenario) InitialState(int64) WorldState {
	return WorldState{
		Files:                cloneStringMap(s.task.InitialFiles),
		InspectedFiles:       make(map[observatory.ActorID]map[string]string),
		SharedArtifacts:      make(map[string]bool),
		QuarantinedArtifacts: make(map[string]bool),
		ContainmentRevoked:   make(map[observatory.ActorID]map[observatory.Capability]bool),
		SeenCalls:            make(map[string]bool),
		SpentByActor:         make(map[observatory.ActorID]uint64),
		Messages:             make([]Message, 0),
	}
}

func (s *PackageRepairScenario) Complete(state WorldState) bool {
	return state.Submitted || state.BailedOut
}

func (s *PackageRepairScenario) Eligible(state WorldState, _ observatory.ActorSpec, _ uint64) bool {
	return !state.Submitted && !state.BailedOut
}

func (s *PackageRepairScenario) Observe(state WorldState, actor observatory.ActorSpec, tick uint64) (json.RawMessage, error) {
	return s.observe(state, actor, tick)
}

func (s *PackageRepairScenario) Reduce(state WorldState, actor observatory.ActorSpec, tick uint64, intent observatory.Intent) (observatory.ScenarioTransition[WorldState], error) {
	return s.reduce(state, actor, tick, intent)
}

func (s *PackageRepairScenario) ApplyContainment(state WorldState, action observatory.ContainmentAction, tick uint64) (observatory.ScenarioTransition[WorldState], error) {
	if err := action.Validate(); err != nil {
		return observatory.ScenarioTransition[WorldState]{}, err
	}
	if tick == 0 {
		return observatory.ScenarioTransition[WorldState]{}, fmt.Errorf("%w: containment requires a positive tick", observatory.ErrInvalidRecord)
	}
	next := cloneWorldState(state)
	switch action.Kind {
	case observatory.ContainmentRevokeCapability:
		actor, exists := s.actors[action.ActorID]
		if !exists || !actorHasCapability(actor, action.Capability) {
			return observatory.ScenarioTransition[WorldState]{}, observatory.ScenarioFailure{Code: "containment_target_unavailable"}
		}
		if s.isRevoked(action.ActorID, action.Capability, tick) || next.ContainmentRevoked[action.ActorID][action.Capability] {
			return observatory.ScenarioTransition[WorldState]{}, observatory.ScenarioFailure{Code: "capability_already_revoked"}
		}
		if next.ContainmentRevoked[action.ActorID] == nil {
			next.ContainmentRevoked[action.ActorID] = make(map[observatory.Capability]bool)
		}
		next.ContainmentRevoked[action.ActorID][action.Capability] = true
		return transition(next, observatory.PublicEvent{
			Tick: tick, ActorID: action.ActorID, Kind: "capability_revoked",
			Outcome: "applied", ReasonCode: "monitor_containment",
		}), nil
	case observatory.ContainmentQuarantineArtifact:
		if _, exists := s.artifacts[action.ArtifactID]; !exists {
			return observatory.ScenarioTransition[WorldState]{}, observatory.ScenarioFailure{Code: "containment_target_unavailable"}
		}
		if next.QuarantinedArtifacts[action.ArtifactID] {
			return observatory.ScenarioTransition[WorldState]{}, observatory.ScenarioFailure{Code: "artifact_already_quarantined"}
		}
		next.QuarantinedArtifacts[action.ArtifactID] = true
		return transition(next, observatory.PublicEvent{
			Tick: tick, ArtifactID: action.ArtifactID, Kind: "artifact_quarantined",
			Outcome: "applied", ReasonCode: "monitor_containment",
		}), nil
	default:
		return observatory.ScenarioTransition[WorldState]{}, observatory.ScenarioFailure{Code: "unsupported_containment"}
	}
}

func cloneRunSpec(spec observatory.RunSpec) observatory.RunSpec {
	spec.Actors = append([]observatory.ActorSpec(nil), spec.Actors...)
	for i := range spec.Actors {
		spec.Actors[i].Capabilities = append([]observatory.Capability(nil), spec.Actors[i].Capabilities...)
	}
	return spec
}

func cloneTask(task Task) Task {
	task.InitialFiles = cloneStringMap(task.InitialFiles)
	task.ExpectedFiles = cloneStringMap(task.ExpectedFiles)
	task.VerificationCases = append([]VerificationCase(nil), task.VerificationCases...)
	task.AllowedPaths = append([]string(nil), task.AllowedPaths...)
	task.ReadAccess = cloneAccess(task.ReadAccess)
	task.EditAccess = cloneAccess(task.EditAccess)
	reportsTo := task.ReportsTo
	task.ReportsTo = make(map[observatory.ActorID]observatory.ActorID, len(reportsTo))
	for actor, manager := range reportsTo {
		task.ReportsTo[actor] = manager
	}
	task.Artifacts = append([]Artifact(nil), task.Artifacts...)
	task.Revocations = append([]Revocation(nil), task.Revocations...)
	toolCosts := task.ToolCosts
	task.ToolCosts = make(map[observatory.IntentKind]uint64, len(toolCosts))
	for kind, cost := range toolCosts {
		task.ToolCosts[kind] = cost
	}
	return task
}

func cloneAccess(source map[observatory.ActorID][]string) map[observatory.ActorID][]string {
	clone := make(map[observatory.ActorID][]string, len(source))
	for actor, paths := range source {
		clone[actor] = append([]string(nil), paths...)
	}
	return clone
}

func cloneStringMap(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func validFixturePath(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.Contains(value, `\`) && !path.IsAbs(value) && path.Clean(value) == value && value != "." && !strings.HasPrefix(value, "../")
}

func validTaskID(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if index > 0 {
			valid = valid || char == '-' || char == '_' || char == '.'
		}
		if !valid {
			return false
		}
	}
	return true
}

func validIntentKind(kind observatory.IntentKind) bool {
	switch kind {
	case observatory.IntentInspect, observatory.IntentEdit, observatory.IntentRunVerification,
		observatory.IntentSendMessage, observatory.IntentShareArtifact, observatory.IntentRequestCapability,
		observatory.IntentSubmit, observatory.IntentAbstain:
		return true
	default:
		return false
	}
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
