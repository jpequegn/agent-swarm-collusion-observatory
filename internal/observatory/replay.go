package observatory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrReplayMismatch = errors.New("replay output differs from source run")

type semanticRunSpec struct {
	ScenarioID      string         `json:"scenario_id"`
	Topology        Topology       `json:"topology"`
	Seed            int64          `json:"seed"`
	BehaviorBundle  BehaviorBundle `json:"behavior_bundle"`
	ProtocolVersion uint32         `json:"protocol_version"`
	Actors          []ActorSpec    `json:"actors"`
	Limits          RunLimits      `json:"limits"`
}

type semanticRunEvidence struct {
	Spec          semanticRunSpec `json:"spec"`
	PublicHead    string          `json:"public_head"`
	PublicCount   uint64          `json:"public_count"`
	TruthHead     string          `json:"truth_head"`
	TruthCount    uint64          `json:"truth_count"`
	DecisionHead  string          `json:"decision_head"`
	DecisionCount uint64          `json:"decision_count"`
	MonitorHead   string          `json:"monitor_head"`
	MonitorCount  uint64          `json:"monitor_count"`
}

// SemanticDigest excludes run identity and replay provenance while binding
// the effective spec, complete input trace, and all derived evidence streams.
func (run VerifiedRun) SemanticDigest() (string, error) {
	bundleDigest, err := run.Spec.BehaviorBundle.Digest()
	if err != nil || bundleDigest != run.Seal.BehaviorBundleDigest {
		return "", fmt.Errorf("%w: invalid behavior bundle in verified run", ErrIntegrity)
	}
	material := semanticRunEvidence{
		Spec: semanticRunSpec{
			ScenarioID:      run.Spec.ScenarioID,
			Topology:        run.Spec.Topology,
			Seed:            run.Spec.Seed,
			BehaviorBundle:  run.Spec.BehaviorBundle,
			ProtocolVersion: run.Spec.ProtocolVersion,
			Actors:          run.Spec.Actors,
			Limits:          run.Spec.Limits,
		},
		PublicHead:    run.Seal.PublicHead,
		PublicCount:   run.Seal.PublicCount,
		TruthHead:     run.Seal.TruthHead,
		TruthCount:    run.Seal.TruthCount,
		DecisionHead:  run.Seal.DecisionHead,
		DecisionCount: run.Seal.DecisionCount,
		MonitorHead:   run.Seal.MonitorHead,
		MonitorCount:  run.Seal.MonitorCount,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	return digestBytes(encoded), nil
}

// Replay verifies a complete source run, then reduces its recorded decisions
// under the exact supported bundle without consulting the policy registry.
func (e *Engine[S]) Replay(ctx context.Context, sourceID, replayID RunID) (RunResult, error) {
	if e == nil || e.Store == nil {
		return RunResult{}, errors.New("engine requires a run store")
	}
	if sourceID == replayID {
		return RunResult{}, fmt.Errorf("%w: replay must use a fresh run ID", ErrInvalidRunID)
	}
	source, err := e.Store.ReadVerifiedRun(sourceID)
	if err != nil {
		return RunResult{}, fmt.Errorf("verify replay source: %w", err)
	}
	if err := e.validateSpec(source.Spec, false); err != nil {
		return RunResult{}, err
	}
	if source.Seal.MonitorCount > 0 && e.Monitor == nil {
		return RunResult{}, fmt.Errorf("%w: source run requires its monitor", ErrUnsupportedBehaviorBundle)
	}
	sealBytes, err := json.Marshal(source.Seal)
	if err != nil {
		return RunResult{}, err
	}
	replaySpec := source.Spec
	replaySpec.RunID = replayID
	replaySpec.SourceRunID = sourceID
	replaySpec.SourceSealDigest = digestBytes(sealBytes)
	if err := replaySpec.Validate(); err != nil {
		return RunResult{}, err
	}
	result, err := e.run(ctx, replaySpec, source.Decisions, true)
	if err != nil {
		return result, err
	}
	sourceDigest, err := source.SemanticDigest()
	if err != nil {
		return result, err
	}
	if result.SemanticDigest != sourceDigest {
		return result, fmt.Errorf("%w: source %s, replay %s", ErrReplayMismatch, sourceDigest, result.SemanticDigest)
	}
	return result, nil
}
