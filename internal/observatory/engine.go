package observatory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

var (
	ErrUnsupportedBehaviorBundle = errors.New("unsupported behavior bundle")
	ErrDecisionTrace             = errors.New("decision trace does not match the scheduled run")
)

const maxObservationBytes = 1 << 20

type AgentObservation struct {
	ScenarioID            string          `json:"scenario_id"`
	Tick                  uint64          `json:"tick"`
	ActorID               ActorID         `json:"actor_id"`
	Capabilities          []Capability    `json:"capabilities"`
	RemainingActionBudget uint64          `json:"remaining_action_budget"`
	Data                  json.RawMessage `json:"data"`
}

type PolicyProposal struct {
	Kind   DecisionKind `json:"kind"`
	Intent *Intent      `json:"intent,omitempty"`
}

type DecisionPolicy interface {
	Identity() PolicyIdentity
	Decide(context.Context, AgentObservation) (PolicyProposal, error)
}

type PolicyFailure struct {
	Code string
}

func (e PolicyFailure) Error() string {
	return e.Code
}

type ScenarioFailure struct {
	Code string
}

func (e ScenarioFailure) Error() string {
	return e.Code
}

type ScenarioTransition[S any] struct {
	NextState    S
	PublicEvents []PublicEvent
	TruthRecords []TruthRecord
}

// Scenario separates immutable observations from state transitions. Observe
// must not mutate state; Reduce returns a new state and must leave its input
// unchanged when it rejects an intent.
type Scenario[S any] interface {
	ID() string
	InitialState(seed int64) S
	Complete(state S) bool
	Eligible(state S, actor ActorSpec, tick uint64) bool
	Observe(state S, actor ActorSpec, tick uint64) (json.RawMessage, error)
	Reduce(state S, actor ActorSpec, tick uint64, intent Intent) (ScenarioTransition[S], error)
}

type Engine[S any] struct {
	Store    *RunStore
	Bundle   BehaviorBundle
	Scenario Scenario[S]
	Policies map[PolicyID]DecisionPolicy
}

type RunResult struct {
	RunID            RunID
	Seal             RunSeal
	SemanticDigest   string
	SourceRunID      RunID
	SourceSealDigest string
}

type scheduledActor struct {
	actor       ActorSpec
	observation AgentObservation
}

func (e *Engine[S]) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	if err := e.validateSpec(spec, true); err != nil {
		return RunResult{}, err
	}
	return e.run(ctx, spec, nil, false)
}

func (e *Engine[S]) validateSpec(spec RunSpec, requirePolicies bool) error {
	if e == nil || e.Store == nil || e.Scenario == nil {
		return errors.New("engine requires a store and scenario")
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if e.Scenario.ID() != spec.ScenarioID {
		return fmt.Errorf("%w: scenario %q is not loaded", ErrInvalidRecord, spec.ScenarioID)
	}
	want, err := e.Bundle.Digest()
	if err != nil {
		return fmt.Errorf("validate supported behavior bundle: %w", err)
	}
	got, err := spec.BehaviorBundle.Digest()
	if err != nil || got != want {
		return ErrUnsupportedBehaviorBundle
	}
	if requirePolicies {
		if spec.SourceRunID != "" {
			return fmt.Errorf("%w: ordinary runs cannot carry replay provenance", ErrInvalidRecord)
		}
		for _, actor := range spec.Actors {
			policy, ok := e.Policies[actor.Policy.ID]
			if !ok || policy == nil {
				return fmt.Errorf("%w: policy %q is not loaded", ErrInvalidRecord, actor.Policy.ID)
			}
			identity := policy.Identity()
			if identity.ID != actor.Policy.ID || identity.Digest != actor.Policy.Digest {
				return fmt.Errorf("%w: policy digest mismatch for %q", ErrInvalidRecord, actor.Policy.ID)
			}
		}
	}
	return nil
}

func (e *Engine[S]) run(ctx context.Context, spec RunSpec, recorded []DecisionRecord, replay bool) (RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := e.validateSpec(spec, !replay); err != nil {
		return RunResult{}, err
	}
	writer, err := e.Store.Reserve(spec)
	if err != nil {
		return RunResult{}, err
	}
	failIncomplete := func(cause error) (RunResult, error) {
		seal, sealErr := writer.Finalize(false)
		result := RunResult{RunID: spec.RunID, Seal: seal, SourceRunID: spec.SourceRunID, SourceSealDigest: spec.SourceSealDigest}
		if sealErr != nil {
			return result, fmt.Errorf("%w; finalize incomplete run: %v", cause, sealErr)
		}
		return result, cause
	}

	actors := append([]ActorSpec(nil), spec.Actors...)
	sort.Slice(actors, func(i, j int) bool { return actors[i].ID < actors[j].ID })
	state := e.Scenario.InitialState(spec.Seed)
	actorActions := make(map[ActorID]uint64, len(actors))
	var totalActions uint64
	decisionIndex := 0
	var decisionCount uint64

	for tick := uint64(1); ; tick++ {
		if err := ctx.Err(); err != nil {
			return failIncomplete(err)
		}
		if e.Scenario.Complete(state) {
			break
		}

		// Build every eligible actor observation before invoking any policy or
		// reducing any action, so each actor sees the same tick-start state.
		scheduled := make([]scheduledActor, 0, len(actors))
		for _, actor := range actors {
			if !e.Scenario.Eligible(state, actor, tick) {
				continue
			}
			data, err := e.Scenario.Observe(state, actor, tick)
			if err != nil {
				return failIncomplete(fmt.Errorf("observe actor %s at tick %d: %w", actor.ID, tick, err))
			}
			if len(data) == 0 || len(data) > maxObservationBytes || !json.Valid(data) {
				return failIncomplete(fmt.Errorf("invalid or oversized observation for actor %s", actor.ID))
			}
			remaining := uint64(0)
			if actorActions[actor.ID] < actor.ActionBudget {
				remaining = actor.ActionBudget - actorActions[actor.ID]
			}
			scheduled = append(scheduled, scheduledActor{
				actor: actor,
				observation: AgentObservation{
					ScenarioID:            spec.ScenarioID,
					Tick:                  tick,
					ActorID:               actor.ID,
					Capabilities:          append([]Capability(nil), actor.Capabilities...),
					RemainingActionBudget: remaining,
					Data:                  bytes.Clone(data),
				},
			})
		}

		for _, scheduledActor := range scheduled {
			if err := ctx.Err(); err != nil {
				return failIncomplete(err)
			}
			actor := scheduledActor.actor
			suppression := ""
			if actorActions[actor.ID] >= actor.ActionBudget {
				suppression = "actor_action_budget_exhausted"
			} else if totalActions >= spec.Limits.MaxTotalActions {
				suppression = "run_action_budget_exhausted"
			}

			var decision DecisionRecord
			if replay {
				if decisionIndex >= len(recorded) {
					return failIncomplete(fmt.Errorf("%w: missing decision for actor %s at tick %d", ErrDecisionTrace, actor.ID, tick))
				}
				decision = recorded[decisionIndex]
				decisionIndex++
				if decision.ActorID != actor.ID || decision.Tick != tick || decision.PolicyID != actor.Policy.ID {
					return failIncomplete(fmt.Errorf("%w: expected actor %s at tick %d", ErrDecisionTrace, actor.ID, tick))
				}
				if suppression != "" {
					if decision.Kind != DecisionSuppressed || decision.SuppressionReason != suppression {
						return failIncomplete(fmt.Errorf("%w: expected suppression %q", ErrDecisionTrace, suppression))
					}
				} else if decision.Kind == DecisionSuppressed {
					return failIncomplete(fmt.Errorf("%w: unexpected suppression for actor %s", ErrDecisionTrace, actor.ID))
				}
			} else if suppression != "" {
				decision = DecisionRecord{
					Tick: tick, ActorID: actor.ID, PolicyID: actor.Policy.ID,
					Kind: DecisionSuppressed, SuppressionReason: suppression,
				}
			} else {
				decision = e.decide(ctx, actor, scheduledActor.observation, tick)
			}
			if err := ctx.Err(); err != nil {
				return failIncomplete(err)
			}
			if err := decision.Validate(); err != nil {
				return failIncomplete(fmt.Errorf("%w: invalid decision for actor %s: %v", ErrDecisionTrace, actor.ID, err))
			}
			if err := writer.AppendDecision(decision); err != nil {
				return failIncomplete(err)
			}
			decisionCount++
			if err := writer.AppendPublic(decisionEvent(decision)); err != nil {
				return failIncomplete(err)
			}

			if decision.Kind != DecisionIntent {
				continue
			}
			actorActions[actor.ID]++
			totalActions++
			capability := requiredCapability(decision.Intent.Kind)
			if capability != "" && !hasCapability(actor.Capabilities, capability) {
				if err := writer.AppendPublic(PublicEvent{
					Tick: tick, ActorID: actor.ID, Kind: "intent_rejected", IntentKind: decision.Intent.Kind,
					Outcome: "rejected", Path: decision.Intent.Path, ReasonCode: "capability_denied",
				}); err != nil {
					return failIncomplete(err)
				}
				continue
			}
			transition, reduceErr := e.Scenario.Reduce(state, actor, tick, *decision.Intent)
			if reduceErr != nil {
				code := reducerFaultCode(reduceErr)
				if err := writer.AppendPublic(PublicEvent{
					Tick: tick, ActorID: actor.ID, Kind: "intent_rejected", IntentKind: decision.Intent.Kind,
					Outcome: "rejected", Path: decision.Intent.Path, ReasonCode: code,
				}); err != nil {
					return failIncomplete(err)
				}
				continue
			}
			if err := appendTransition(writer, transition, actor, tick); err != nil {
				return failIncomplete(err)
			}
			state = transition.NextState
		}
		if e.Scenario.Complete(state) {
			break
		}
		if tick == spec.Limits.MaxTicks {
			break
		}
	}
	if replay && decisionIndex != len(recorded) {
		return failIncomplete(fmt.Errorf("%w: %d unexpected decisions remain", ErrDecisionTrace, len(recorded)-decisionIndex))
	}
	if decisionCount == 0 {
		return failIncomplete(fmt.Errorf("%w: no actor decisions were scheduled", ErrIncompleteRun))
	}
	seal, err := writer.Finalize(true)
	if errors.Is(err, ErrCommitIndeterminate) {
		seal, err = e.Store.Verify(spec.RunID)
	}
	if err != nil {
		return RunResult{RunID: spec.RunID, Seal: seal, SourceRunID: spec.SourceRunID, SourceSealDigest: spec.SourceSealDigest}, err
	}
	verified, err := e.Store.ReadVerifiedRun(spec.RunID)
	if err != nil {
		return RunResult{RunID: spec.RunID, Seal: seal, SourceRunID: spec.SourceRunID, SourceSealDigest: spec.SourceSealDigest}, err
	}
	semanticDigest, err := verified.SemanticDigest()
	if err != nil {
		return RunResult{}, err
	}
	return RunResult{
		RunID: spec.RunID, Seal: seal, SemanticDigest: semanticDigest,
		SourceRunID: spec.SourceRunID, SourceSealDigest: spec.SourceSealDigest,
	}, nil
}

func (e *Engine[S]) decide(ctx context.Context, actor ActorSpec, observation AgentObservation, tick uint64) DecisionRecord {
	policy := e.Policies[actor.Policy.ID]
	proposal, err := policy.Decide(ctx, observation)
	if err != nil {
		code := policyFaultCode(err)
		if code == "" {
			code = "policy_error"
			if errors.Is(err, context.DeadlineExceeded) {
				code = "timeout"
			}
		}
		return DecisionRecord{Tick: tick, ActorID: actor.ID, PolicyID: actor.Policy.ID, Kind: DecisionPolicyFault, FaultCode: code}
	}
	decision := DecisionRecord{Tick: tick, ActorID: actor.ID, PolicyID: actor.Policy.ID, Kind: proposal.Kind, Intent: proposal.Intent}
	if decision.Kind != DecisionIntent && decision.Kind != DecisionNoAction {
		return DecisionRecord{Tick: tick, ActorID: actor.ID, PolicyID: actor.Policy.ID, Kind: DecisionPolicyFault, FaultCode: "invalid_policy_response"}
	}
	if err := decision.Validate(); err != nil {
		return DecisionRecord{Tick: tick, ActorID: actor.ID, PolicyID: actor.Policy.ID, Kind: DecisionPolicyFault, FaultCode: "invalid_intent"}
	}
	return decision
}

func decisionEvent(decision DecisionRecord) PublicEvent {
	event := PublicEvent{
		Tick: decision.Tick, ActorID: decision.ActorID, Kind: "decision",
		Outcome: string(decision.Kind), ReasonCode: decision.FaultCode,
	}
	if decision.Kind == DecisionSuppressed {
		event.ReasonCode = decision.SuppressionReason
	}
	if decision.Intent != nil {
		event.IntentKind = decision.Intent.Kind
		event.Path = decision.Intent.Path
		if decision.Intent.Content != "" {
			event.ContentDigest = digestBytes([]byte(decision.Intent.Content))
		}
	}
	return event
}

func requiredCapability(kind IntentKind) Capability {
	switch kind {
	case IntentInspect:
		return "inspect"
	case IntentEdit:
		return "edit"
	case IntentRunVerification:
		return "verify"
	case IntentSendMessage:
		return "communicate"
	case IntentShareArtifact:
		return "share_artifact"
	case IntentRequestCapability:
		return "request_capability"
	case IntentSubmit:
		return "submit"
	default:
		return ""
	}
}

func hasCapability(capabilities []Capability, want Capability) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

func reducerFaultCode(err error) string {
	if code := scenarioFaultCode(err); code != "" {
		return code
	}
	return "reducer_rejected"
}

func policyFaultCode(err error) string {
	var value PolicyFailure
	if errors.As(err, &value) && validToken(value.Code, 96) {
		return value.Code
	}
	var pointer *PolicyFailure
	if errors.As(err, &pointer) && pointer != nil && validToken(pointer.Code, 96) {
		return pointer.Code
	}
	return ""
}

func scenarioFaultCode(err error) string {
	var value ScenarioFailure
	if errors.As(err, &value) && validToken(value.Code, 96) {
		return value.Code
	}
	var pointer *ScenarioFailure
	if errors.As(err, &pointer) && pointer != nil && validToken(pointer.Code, 96) {
		return pointer.Code
	}
	return ""
}

func appendTransition[S any](writer *RunWriter, transition ScenarioTransition[S], actor ActorSpec, tick uint64) error {
	for _, event := range transition.PublicEvents {
		if event.Tick == 0 {
			event.Tick = tick
		}
		if event.Tick != tick {
			return fmt.Errorf("scenario event tick %d does not match current tick %d", event.Tick, tick)
		}
		if event.ActorID == "" {
			event.ActorID = actor.ID
		}
		if event.ActorID != actor.ID {
			return fmt.Errorf("scenario event actor %q does not match actor %q", event.ActorID, actor.ID)
		}
		if err := writer.AppendPublic(event); err != nil {
			return err
		}
	}
	for _, record := range transition.TruthRecords {
		if record.Tick == 0 {
			record.Tick = tick
		}
		if record.Tick != tick {
			return fmt.Errorf("scenario truth tick %d does not match current tick %d", record.Tick, tick)
		}
		if err := writer.AppendTruth(record); err != nil {
			return err
		}
	}
	return nil
}
