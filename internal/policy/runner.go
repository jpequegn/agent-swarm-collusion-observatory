package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

const protocolVersion uint32 = 1

const (
	maxPolicyInputBytes  = 1 << 20
	maxPolicyOutputBytes = 64 << 10
	maxPolicyStderrBytes = 16 << 10
	maxPolicyTimeout     = 30 * time.Second
)

const expectedRunnerDigest = "b91033228758c6cb3becd07931c9804196784e234fab2512337d94d0855c27a5"

type Name string

const (
	HonestRepair          Name = "honest_repair"
	NoAction              Name = "no_action"
	DuplicateInspector    Name = "duplicate_inspector"
	RewardGamer           Name = "reward_gamer"
	WrongVersionProbe     Name = "wrong_version_probe"
	MalformedOutputProbe  Name = "malformed_output_probe"
	OversizedOutputProbe  Name = "oversized_output_probe"
	TimeoutProbe          Name = "timeout_probe"
	UnauthorizedEditProbe Name = "unauthorized_edit_probe"
	UnknownActionProbe    Name = "unknown_action_probe"
	StderrProbe           Name = "stderr_probe"
)

type Limits struct {
	InputBytes  int
	OutputBytes int
	StderrBytes int
	Timeout     time.Duration
}

type BundledPython struct {
	name       Name
	identity   observatory.PolicyIdentity
	executable string
	scriptPath string
	scriptHash string
	limits     Limits
}

type policyRequest struct {
	ProtocolVersion       uint32                   `json:"protocol_version"`
	ScenarioID            string                   `json:"scenario_id"`
	Tick                  uint64                   `json:"tick"`
	ActorID               observatory.ActorID      `json:"actor_id"`
	Capabilities          []observatory.Capability `json:"capabilities"`
	RemainingActionBudget uint64                   `json:"remaining_action_budget"`
	Observation           json.RawMessage          `json:"observation"`
}

type policyResponse struct {
	ProtocolVersion uint32                      `json:"protocol_version"`
	Proposal        *observatory.PolicyProposal `json:"proposal,omitempty"`
	Error           string                      `json:"error,omitempty"`
}

var (
	errOutputLimit   = errors.New("policy output limit exceeded")
	errStderrLimit   = errors.New("policy stderr limit exceeded")
	errPolicyTimeout = errors.New("policy timed out")
	errProcessFailed = errors.New("policy process failed")
)

func DefaultLimits() Limits {
	return Limits{InputBytes: 256 << 10, OutputBytes: 16 << 10, StderrBytes: 4 << 10, Timeout: 2 * time.Second}
}

// NewBundledPython loads only the fixed, checked-in runner and policy catalog.
// The source digest is pinned in this Go package to reject modified scripts.
func NewBundledPython(repositoryRoot string, name Name, limits Limits) (*BundledPython, error) {
	if !knownName(name) {
		return nil, fmt.Errorf("unknown bundled Python policy %q", name)
	}
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	scriptPath := filepath.Join(root, "python", "observatory_policies", "runner.py")
	info, err := os.Lstat(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("locate bundled policy runner: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("bundled policy runner must be a regular file")
	}
	source, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("read bundled policy runner: %w", err)
	}
	actualSourceDigest := digest(source)
	if expectedRunnerDigest == "" || actualSourceDigest != expectedRunnerDigest {
		return nil, errors.New("bundled policy source digest does not match the reviewed runner")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		return nil, fmt.Errorf("locate Python 3 runtime: %w", err)
	}
	python, err = filepath.Abs(python)
	if err != nil {
		return nil, fmt.Errorf("resolve Python 3 runtime: %w", err)
	}
	return &BundledPython{
		name:       name,
		identity:   observatory.PolicyIdentity{ID: observatory.PolicyID("python-" + string(name)), Digest: policyDigest(name, source)},
		executable: python, scriptPath: scriptPath, scriptHash: actualSourceDigest, limits: limits,
	}, nil
}

func (p *BundledPython) Identity() observatory.PolicyIdentity {
	if p == nil {
		return observatory.PolicyIdentity{}
	}
	return p.identity
}

func (p *BundledPython) Decide(ctx context.Context, observation observatory.AgentObservation) (observatory.PolicyProposal, error) {
	if p == nil {
		return observatory.PolicyProposal{}, errors.New("bundled policy is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !validToken(observation.ScenarioID) || !validToken(string(observation.ActorID)) || observation.Tick == 0 {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "invalid_identity"}
	}
	if observation.RemainingActionBudget == 0 {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "action_budget_exhausted"}
	}
	if !isJSONObservation(observation.Data) {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "invalid_observation"}
	}
	seenCapabilities := make(map[observatory.Capability]struct{}, len(observation.Capabilities))
	for _, capability := range observation.Capabilities {
		if !knownCapability(capability) {
			return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "invalid_observation"}
		}
		if _, exists := seenCapabilities[capability]; exists {
			return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "invalid_observation"}
		}
		seenCapabilities[capability] = struct{}{}
	}
	request := policyRequest{
		ProtocolVersion: protocolVersion, ScenarioID: observation.ScenarioID, Tick: observation.Tick,
		ActorID: observation.ActorID, Capabilities: append([]observatory.Capability(nil), observation.Capabilities...),
		RemainingActionBudget: observation.RemainingActionBudget, Observation: bytes.Clone(observation.Data),
	}
	input, err := json.Marshal(request)
	if err != nil {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "invalid_observation"}
	}
	input = append(input, '\n')
	if len(input) > p.limits.InputBytes {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "input_limit"}
	}
	source, err := os.ReadFile(p.scriptPath)
	if err != nil || digest(source) != p.scriptHash {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "bundle_changed"}
	}
	output, err := runBounded(ctx, p.executable, string(source), p.name, input, p.limits)
	if err != nil {
		var failure observatory.PolicyFailure
		if errors.As(err, &failure) {
			return observatory.PolicyProposal{}, failure
		}
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "process_error"}
	}
	return decodeResponse(output, observation, p.identity.ID)
}

func decodeResponse(output []byte, observation observatory.AgentObservation, policyID observatory.PolicyID) (observatory.PolicyProposal, error) {
	if len(output) == 0 || !utf8.Valid(output) || output[len(output)-1] != '\n' || bytes.Count(output, []byte{'\n'}) != 1 || bytes.Contains(output, []byte{'\r'}) {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "malformed_response"}
	}
	var response policyResponse
	decoder := json.NewDecoder(bytes.NewReader(output[:len(output)-1]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "malformed_response"}
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "malformed_response"}
	}
	if response.ProtocolVersion != protocolVersion {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "protocol_version_mismatch"}
	}
	if response.Error != "" {
		if response.Proposal != nil || !validToken(response.Error) {
			return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "protocol_error"}
		}
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: response.Error}
	}
	if response.Proposal == nil || response.Proposal.Kind != observatory.DecisionIntent && response.Proposal.Kind != observatory.DecisionNoAction {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "invalid_policy_response"}
	}
	decision := observatory.DecisionRecord{
		Tick: observation.Tick, ActorID: observation.ActorID, PolicyID: policyID,
		Kind: response.Proposal.Kind, Intent: response.Proposal.Intent,
	}
	if err := decision.Validate(); err != nil {
		return observatory.PolicyProposal{}, observatory.PolicyFailure{Code: "invalid_policy_response"}
	}
	return *response.Proposal, nil
}

func runBounded(ctx context.Context, executable, source string, name Name, input []byte, limits Limits) ([]byte, error) {
	command := exec.Command(executable, "-I", "-S", "-B", "-c", source, string(name))
	command.Dir = os.TempDir()
	command.Env = []string{"PYTHONHASHSEED=0", "PYTHONIOENCODING=utf-8", "PYTHONDONTWRITEBYTECODE=1"}
	return runBoundedCommand(ctx, command, input, limits)
}

func runBoundedCommand(ctx context.Context, command *exec.Cmd, input []byte, limits Limits) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	if err := configureProcessGroup(command); err != nil {
		return nil, err
	}
	if err := runCtx.Err(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, observatory.PolicyFailure{Code: "timeout"}
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, errProcessFailed
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errProcessFailed
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, errProcessFailed
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("%w: start: %v", errProcessFailed, err)
	}
	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			_ = terminateProcessGroup(command)
		case <-stopCancel:
		}
	}()
	type readResult struct {
		data []byte
		err  error
	}
	stdoutDone := make(chan readResult, 1)
	stderrDone := make(chan readResult, 1)
	inputDone := make(chan error, 1)
	go func() {
		data, readErr := readLimited(stdout, limits.OutputBytes, errOutputLimit)
		stdoutDone <- readResult{data, readErr}
	}()
	go func() {
		data, readErr := readLimited(stderr, limits.StderrBytes, errStderrLimit)
		stderrDone <- readResult{data, readErr}
	}()
	go func() {
		_, writeErr := stdin.Write(input)
		closeErr := stdin.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
		inputDone <- writeErr
	}()

	var output []byte
	var failure error
	remaining := 3
	ctxDone := runCtx.Done()
	for remaining > 0 {
		select {
		case result := <-stdoutDone:
			output = result.data
			remaining--
			if result.err != nil && failure == nil {
				failure = result.err
				cancel()
			}
		case result := <-stderrDone:
			remaining--
			if result.err != nil && failure == nil {
				failure = result.err
				cancel()
			}
		case writeErr := <-inputDone:
			remaining--
			if writeErr != nil && failure == nil && runCtx.Err() == nil {
				failure = errProcessFailed
				cancel()
			}
		case <-ctxDone:
			if ctx.Err() != nil {
				failure = ctx.Err()
			} else if failure == nil {
				failure = errPolicyTimeout
			}
			cancel()
			ctxDone = nil
		}
	}
	waitErr := command.Wait()
	close(stopCancel)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(failure, errPolicyTimeout) {
		return nil, observatory.PolicyFailure{Code: "timeout"}
	}
	if errors.Is(failure, errOutputLimit) {
		return nil, observatory.PolicyFailure{Code: "output_limit"}
	}
	if errors.Is(failure, errStderrLimit) {
		return nil, observatory.PolicyFailure{Code: "stderr_limit"}
	}
	if failure != nil || waitErr != nil {
		return nil, fmt.Errorf("%w: wait: %v", errProcessFailed, waitErr)
	}
	return output, nil
}

func readLimited(reader io.Reader, limit int, limitError error) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if len(data) > limit {
		return data[:limit], limitError
	}
	return data, err
}

func validateLimits(limits Limits) error {
	if limits.InputBytes <= 0 || limits.InputBytes > maxPolicyInputBytes || limits.OutputBytes <= 0 || limits.OutputBytes > maxPolicyOutputBytes || limits.StderrBytes <= 0 || limits.StderrBytes > maxPolicyStderrBytes || limits.Timeout <= 0 || limits.Timeout > maxPolicyTimeout {
		return errors.New("policy limits must be positive and within the runner's hard caps")
	}
	return nil
}

func knownName(name Name) bool {
	switch name {
	case HonestRepair, NoAction, DuplicateInspector, RewardGamer, WrongVersionProbe, MalformedOutputProbe, OversizedOutputProbe, TimeoutProbe, UnauthorizedEditProbe, UnknownActionProbe, StderrProbe:
		return true
	default:
		return false
	}
}

func knownCapability(capability observatory.Capability) bool {
	switch capability {
	case "inspect", "edit", "verify", "communicate", "share_artifact", "request_capability", "submit", "abstain":
		return true
	default:
		return false
	}
}

func validToken(value string) bool {
	if len(value) == 0 || len(value) > 96 {
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

func isJSONObservation(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(trimmed) && utf8.Valid(trimmed)
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func policyDigest(name Name, source []byte) string {
	return digest([]byte(strings.Join([]string{string(name), "protocol-v1", string(source)}, "\x00")))
}
