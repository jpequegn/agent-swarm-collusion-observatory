package observatory

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

var ErrInvalidRunID = errors.New("invalid run ID")
var ErrInvalidRecord = errors.New("invalid run record")

type RunID string
type ActorID string
type PolicyID string
type Capability string

func ParseRunID(value string) (RunID, error) {
	if len(value) == 0 || len(value) > 128 {
		return "", fmt.Errorf("%w: length must be between 1 and 128", ErrInvalidRunID)
	}
	for i, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if i > 0 {
			valid = valid || r == '-' || r == '_' || r == '.'
		}
		if !valid {
			return "", fmt.Errorf("%w: unsupported character", ErrInvalidRunID)
		}
	}
	return RunID(value), nil
}

type BehaviorBundle struct {
	EngineVersion         string `json:"engine_version"`
	MonitorVersion        string `json:"monitor_version"`
	ContainmentVersion    string `json:"containment_version"`
	EvaluatorVersion      string `json:"evaluator_version"`
	PolicyProtocolVersion string `json:"policy_protocol_version"`
	BuildDigest           string `json:"build_digest"`
}

func (b BehaviorBundle) Validate() error {
	if !validToken(b.EngineVersion, 96) || !validToken(b.MonitorVersion, 96) || !validToken(b.ContainmentVersion, 96) || !validToken(b.EvaluatorVersion, 96) || !validToken(b.PolicyProtocolVersion, 96) || !isDigest(b.BuildDigest) {
		return errors.New("behavior bundle requires version tokens and a lowercase SHA-256 build digest")
	}
	return nil
}

func (b BehaviorBundle) Digest() (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return digestBytes(encoded), nil
}

type Topology string

const (
	TopologySharedMessages Topology = "shared_messages"
	TopologyHierarchical   Topology = "hierarchical"
)

type PolicyIdentity struct {
	ID     PolicyID `json:"id"`
	Digest string   `json:"digest"`
}

type ActorSpec struct {
	ID           ActorID        `json:"id"`
	Role         string         `json:"role"`
	Policy       PolicyIdentity `json:"policy"`
	Capabilities []Capability   `json:"capabilities"`
	ActionBudget uint64         `json:"action_budget"`
	SpendBudget  uint64         `json:"spend_budget"`
}

type RunLimits struct {
	MaxTicks        uint64 `json:"max_ticks"`
	MaxTotalActions uint64 `json:"max_total_actions"`
	MaxTotalSpend   uint64 `json:"max_total_spend"`
	MaxOutputBytes  uint64 `json:"max_output_bytes"`
	MaxStderrBytes  uint64 `json:"max_stderr_bytes"`
}

type RunSpec struct {
	RunID           RunID          `json:"run_id"`
	ScenarioID      string         `json:"scenario_id"`
	Topology        Topology       `json:"topology"`
	Seed            int64          `json:"seed"`
	BehaviorBundle  BehaviorBundle `json:"behavior_bundle"`
	ProtocolVersion uint32         `json:"protocol_version"`
	Actors          []ActorSpec    `json:"actors"`
	Limits          RunLimits      `json:"limits"`
}

func (s RunSpec) Validate() error {
	if _, err := ParseRunID(string(s.RunID)); err != nil {
		return err
	}
	if !validToken(s.ScenarioID, 96) {
		return fmt.Errorf("%w: invalid scenario ID", ErrInvalidRecord)
	}
	if s.Topology != TopologySharedMessages && s.Topology != TopologyHierarchical {
		return fmt.Errorf("%w: unsupported topology", ErrInvalidRecord)
	}
	if err := s.BehaviorBundle.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if s.ProtocolVersion == 0 || len(s.Actors) == 0 || len(s.Actors) > 64 || s.Limits.MaxTicks == 0 || s.Limits.MaxTotalActions == 0 || s.Limits.MaxOutputBytes == 0 {
		return fmt.Errorf("%w: missing protocol, actors, or positive run limits", ErrInvalidRecord)
	}
	seen := make(map[ActorID]struct{}, len(s.Actors))
	for _, actor := range s.Actors {
		if !validToken(string(actor.ID), 96) || !validToken(actor.Role, 96) || !validToken(string(actor.Policy.ID), 96) || !isDigest(actor.Policy.Digest) {
			return fmt.Errorf("%w: invalid actor or policy identity", ErrInvalidRecord)
		}
		if _, exists := seen[actor.ID]; exists {
			return fmt.Errorf("%w: duplicate actor ID %q", ErrInvalidRecord, actor.ID)
		}
		seen[actor.ID] = struct{}{}
		if len(actor.Capabilities) > 64 {
			return fmt.Errorf("%w: too many actor capabilities", ErrInvalidRecord)
		}
		caps := make(map[Capability]struct{}, len(actor.Capabilities))
		for _, capability := range actor.Capabilities {
			if !validToken(string(capability), 96) {
				return fmt.Errorf("%w: invalid capability", ErrInvalidRecord)
			}
			if _, exists := caps[capability]; exists {
				return fmt.Errorf("%w: duplicate capability %q", ErrInvalidRecord, capability)
			}
			caps[capability] = struct{}{}
		}
	}
	return nil
}

type IntentKind string

const (
	IntentInspect           IntentKind = "inspect"
	IntentEdit              IntentKind = "edit"
	IntentRunVerification   IntentKind = "run_verification"
	IntentSendMessage       IntentKind = "send_message"
	IntentShareArtifact     IntentKind = "share_artifact"
	IntentRequestCapability IntentKind = "request_capability"
	IntentSubmit            IntentKind = "submit"
	IntentAbstain           IntentKind = "abstain"
)

type Intent struct {
	Kind       IntentKind `json:"kind"`
	Path       string     `json:"path,omitempty"`
	Content    string     `json:"content,omitempty"`
	Recipient  ActorID    `json:"recipient,omitempty"`
	Message    string     `json:"message,omitempty"`
	ArtifactID string     `json:"artifact_id,omitempty"`
	Capability Capability `json:"capability,omitempty"`
}

func (i Intent) Validate() error {
	if !utf8.ValidString(i.Path) || !utf8.ValidString(i.Content) || !utf8.ValidString(string(i.Recipient)) || !utf8.ValidString(i.Message) || !utf8.ValidString(i.ArtifactID) || !utf8.ValidString(string(i.Capability)) {
		return fmt.Errorf("%w: intent contains invalid UTF-8", ErrInvalidRecord)
	}
	if i.Recipient != "" && !validToken(string(i.Recipient), 96) || i.ArtifactID != "" && !validToken(i.ArtifactID, 96) || i.Capability != "" && !validToken(string(i.Capability), 96) {
		return fmt.Errorf("%w: invalid intent identity", ErrInvalidRecord)
	}
	noPath := i.Path == ""
	noContent := i.Content == ""
	noRecipient := i.Recipient == ""
	noMessage := i.Message == ""
	noArtifact := i.ArtifactID == ""
	noCapability := i.Capability == ""
	valid := false
	switch i.Kind {
	case IntentInspect:
		valid = !noPath && noContent && noRecipient && noMessage && noArtifact && noCapability
	case IntentEdit:
		valid = !noPath && !noContent && noRecipient && noMessage && noArtifact && noCapability
	case IntentRunVerification, IntentSubmit, IntentAbstain:
		valid = noPath && noContent && noRecipient && noMessage && noArtifact && noCapability
	case IntentSendMessage:
		valid = noPath && noContent && !noRecipient && !noMessage && noArtifact && noCapability
	case IntentShareArtifact:
		valid = noPath && noContent && noRecipient && noMessage && !noArtifact && noCapability
	case IntentRequestCapability:
		valid = noPath && noContent && noRecipient && noMessage && noArtifact && !noCapability
	}
	if !valid {
		return fmt.Errorf("%w: invalid %q intent fields", ErrInvalidRecord, i.Kind)
	}
	return nil
}

type DecisionKind string

const (
	DecisionIntent      DecisionKind = "intent"
	DecisionNoAction    DecisionKind = "no_action"
	DecisionPolicyFault DecisionKind = "policy_fault"
	DecisionSuppressed  DecisionKind = "suppressed"
)

type DecisionRecord struct {
	Tick              uint64       `json:"tick"`
	ActorID           ActorID      `json:"actor_id"`
	PolicyID          PolicyID     `json:"policy_id"`
	Kind              DecisionKind `json:"kind"`
	Intent            *Intent      `json:"intent,omitempty"`
	FaultCode         string       `json:"fault_code,omitempty"`
	SuppressionReason string       `json:"suppression_reason,omitempty"`
}

func (d DecisionRecord) Validate() error {
	if !validToken(string(d.ActorID), 96) || !validToken(string(d.PolicyID), 96) {
		return fmt.Errorf("%w: invalid decision actor or policy", ErrInvalidRecord)
	}
	switch d.Kind {
	case DecisionIntent:
		if d.Intent == nil || d.FaultCode != "" || d.SuppressionReason != "" {
			return fmt.Errorf("%w: intent decision must contain only an intent", ErrInvalidRecord)
		}
		return d.Intent.Validate()
	case DecisionNoAction:
		if d.Intent != nil || d.FaultCode != "" || d.SuppressionReason != "" {
			return fmt.Errorf("%w: no-action decision has unexpected data", ErrInvalidRecord)
		}
	case DecisionPolicyFault:
		if d.Intent != nil || !validToken(d.FaultCode, 96) || d.SuppressionReason != "" {
			return fmt.Errorf("%w: invalid policy-fault decision", ErrInvalidRecord)
		}
	case DecisionSuppressed:
		if d.Intent != nil || d.FaultCode != "" || !validToken(d.SuppressionReason, 96) {
			return fmt.Errorf("%w: invalid suppressed decision", ErrInvalidRecord)
		}
	default:
		return fmt.Errorf("%w: unsupported decision kind %q", ErrInvalidRecord, d.Kind)
	}
	return nil
}

type PublicEvent struct {
	Tick          uint64     `json:"tick"`
	ActorID       ActorID    `json:"actor_id,omitempty"`
	Kind          string     `json:"kind"`
	IntentKind    IntentKind `json:"intent_kind,omitempty"`
	Outcome       string     `json:"outcome"`
	Path          string     `json:"path,omitempty"`
	ArtifactID    string     `json:"artifact_id,omitempty"`
	Recipient     ActorID    `json:"recipient,omitempty"`
	Message       string     `json:"message,omitempty"`
	ContentDigest string     `json:"content_digest,omitempty"`
	ReasonCode    string     `json:"reason_code,omitempty"`
}

type TruthRecord struct {
	Tick           uint64  `json:"tick"`
	FactKind       string  `json:"fact_kind"`
	ActorID        ActorID `json:"actor_id,omitempty"`
	ArtifactID     string  `json:"artifact_id,omitempty"`
	ExpectedDigest string  `json:"expected_digest,omitempty"`
	ActualDigest   string  `json:"actual_digest,omitempty"`
	Value          bool    `json:"value"`
}

type MonitorObservation struct {
	Sequence      uint64     `json:"sequence"`
	Tick          uint64     `json:"tick"`
	ActorID       ActorID    `json:"actor_id,omitempty"`
	EventKind     string     `json:"event_kind"`
	IntentKind    IntentKind `json:"intent_kind,omitempty"`
	Outcome       string     `json:"outcome"`
	Resource      string     `json:"resource,omitempty"`
	ContentDigest string     `json:"content_digest,omitempty"`
	ReasonCode    string     `json:"reason_code,omitempty"`
}

type RunSeal struct {
	SpecDigest           string `json:"spec_digest"`
	BehaviorBundleDigest string `json:"behavior_bundle_digest"`
	PublicHead           string `json:"public_head"`
	PublicCount          uint64 `json:"public_count"`
	TruthHead            string `json:"truth_head"`
	TruthCount           uint64 `json:"truth_count"`
	DecisionHead         string `json:"decision_head"`
	DecisionCount        uint64 `json:"decision_count"`
	Completed            bool   `json:"completed"`
}

func validToken(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for i, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if i > 0 {
			valid = valid || r == '-' || r == '_' || r == '.'
		}
		if !valid {
			return false
		}
	}
	return true
}

func isDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
