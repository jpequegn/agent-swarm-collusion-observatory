package observatory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"
)

var (
	ErrRunExists           = errors.New("run ID already exists")
	ErrIncompleteRun       = errors.New("run is incomplete")
	ErrIntegrity           = errors.New("run integrity verification failed")
	ErrWriterClosed        = errors.New("run writer is closed")
	ErrFileTooLarge        = errors.New("run evidence file exceeds size limit")
	ErrCommitIndeterminate = errors.New("run seal published but directory sync failed; verify the same run ID")
)

const (
	maxStreamBytes = 64 << 20
	maxRecordBytes = 8 << 20
	maxSpecBytes   = 4 << 20
)

type RunStore struct {
	root string
}

type VerifiedRun struct {
	Spec         RunSpec
	Seal         RunSeal
	PublicEvents []PublicEvent
	TruthRecords []TruthRecord
	Decisions    []DecisionRecord
}

type streamWriter struct {
	file  *os.File
	name  string
	head  string
	count uint64
	size  int64
}

type RunWriter struct {
	mu           sync.Mutex
	dir          string
	specDigest   string
	bundleDigest string
	public       streamWriter
	truth        streamWriter
	decisions    streamWriter
	closed       bool
	failed       error
}

type chainEnvelope struct {
	Sequence     uint64          `json:"sequence"`
	PreviousHash string          `json:"previous_hash"`
	Payload      json.RawMessage `json:"payload"`
	Hash         string          `json:"hash"`
}

type chainBody struct {
	Sequence     uint64          `json:"sequence"`
	PreviousHash string          `json:"previous_hash"`
	Payload      json.RawMessage `json:"payload"`
}

func NewRunStore(root string) (*RunStore, error) {
	if root == "" {
		return nil, errors.New("run store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create run store root: %w", err)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve run store root: %w", err)
	}
	if err := syncDirectoryChain(absRoot); err != nil {
		return nil, fmt.Errorf("sync run store directory chain: %w", err)
	}
	return &RunStore{root: absRoot}, nil
}

// Reserve atomically claims a run ID by creating its directory. A failed or
// interrupted reservation is deliberately left incomplete and is not reused.
func (s *RunStore) Reserve(spec RunSpec) (*RunWriter, error) {
	if s == nil {
		return nil, errors.New("run store is nil")
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode run spec: %w", err)
	}
	bundleDigest, err := spec.BehaviorBundle.Digest()
	if err != nil {
		return nil, err
	}
	if int64(len(specBytes)+1) > maxSpecBytes {
		return nil, ErrFileTooLarge
	}
	specDigest := digestBytes(specBytes)
	dir := filepath.Join(s.root, string(spec.RunID))
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrRunExists, spec.RunID)
		}
		return nil, fmt.Errorf("reserve run ID: %w", err)
	}
	if err := syncDirectory(s.root); err != nil {
		return nil, fmt.Errorf("sync run ID reservation: %w", err)
	}
	if err := writeExclusive(filepath.Join(dir, "spec.json"), append(specBytes, '\n')); err != nil {
		return nil, fmt.Errorf("write run spec: %w", err)
	}

	w := &RunWriter{
		dir:          dir,
		specDigest:   specDigest,
		bundleDigest: bundleDigest,
	}
	streams := []*streamWriter{
		{name: "public.jsonl"},
		{name: "truth.jsonl"},
		{name: "decisions.jsonl"},
	}
	for _, stream := range streams {
		file, openErr := os.OpenFile(filepath.Join(dir, stream.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if openErr != nil {
			w.closeStreams()
			return nil, fmt.Errorf("create %s: %w", stream.name, openErr)
		}
		stream.file = file
		switch stream.name {
		case "public.jsonl":
			w.public = *stream
		case "truth.jsonl":
			w.truth = *stream
		case "decisions.jsonl":
			w.decisions = *stream
		}
	}
	return w, nil
}

func (w *RunWriter) AppendPublic(event PublicEvent) error {
	if w == nil {
		return errors.New("run writer is nil")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	return w.append(&w.public, event)
}

func (w *RunWriter) AppendTruth(record TruthRecord) error {
	if w == nil {
		return errors.New("run writer is nil")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	return w.append(&w.truth, record)
}

func (w *RunWriter) AppendDecision(record DecisionRecord) error {
	if w == nil {
		return errors.New("run writer is nil")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	return w.append(&w.decisions, record)
}

func (w *RunWriter) append(stream *streamWriter, value any) error {
	if w == nil {
		return errors.New("run writer is nil")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWriterClosed
	}
	if w.failed != nil {
		return fmt.Errorf("run writer is unusable: %w", w.failed)
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s record: %w", stream.name, err)
	}
	sequence := stream.count + 1
	body := chainBody{Sequence: sequence, PreviousHash: stream.head, Payload: payload}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode %s chain body: %w", stream.name, err)
	}
	hash := digestBytes(bodyBytes)
	envelope := chainEnvelope{Sequence: sequence, PreviousHash: stream.head, Payload: payload, Hash: hash}
	line, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode %s chain entry: %w", stream.name, err)
	}
	line = append(line, '\n')
	if len(line) > maxRecordBytes || stream.size+int64(len(line)) > maxStreamBytes {
		w.failed = ErrFileTooLarge
		return ErrFileTooLarge
	}
	if err := writeFull(stream.file, line); err != nil {
		w.failed = err
		return fmt.Errorf("append %s record: %w", stream.name, err)
	}
	stream.head = hash
	stream.count = sequence
	stream.size += int64(len(line))
	return nil
}

// Finalize writes a seal only after all three streams have been synced. If the
// seal is published but directory sync fails, callers must Verify the same run
// ID before deciding whether to retry. The engine must establish full schedule
// coverage before passing completed=true. A finalized incomplete run carries
// Completed=false and cannot verify as valid.
func (w *RunWriter) Finalize(completed bool) (RunSeal, error) {
	if w == nil {
		return RunSeal{}, errors.New("run writer is nil")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return RunSeal{}, ErrWriterClosed
	}
	if w.failed != nil {
		w.closeStreams()
		w.closed = true
		return RunSeal{}, fmt.Errorf("run writer is unusable: %w", w.failed)
	}
	if completed && w.decisions.count == 0 {
		_ = w.closeStreams()
		w.closed = true
		return RunSeal{}, fmt.Errorf("%w: completed runs require a decision trace", ErrIncompleteRun)
	}
	var syncErr error
	for _, stream := range []*streamWriter{&w.public, &w.truth, &w.decisions} {
		if err := stream.file.Sync(); err != nil && syncErr == nil {
			syncErr = err
		}
	}
	closeErr := w.closeStreams()
	w.closed = true
	if syncErr != nil {
		return RunSeal{}, fmt.Errorf("sync run streams: %w", syncErr)
	}
	if closeErr != nil {
		return RunSeal{}, fmt.Errorf("close run streams: %w", closeErr)
	}
	seal := RunSeal{
		SpecDigest:           w.specDigest,
		BehaviorBundleDigest: w.bundleDigest,
		PublicHead:           w.public.head,
		PublicCount:          w.public.count,
		TruthHead:            w.truth.head,
		TruthCount:           w.truth.count,
		DecisionHead:         w.decisions.head,
		DecisionCount:        w.decisions.count,
		Completed:            completed,
	}
	encoded, err := json.Marshal(seal)
	if err != nil {
		return RunSeal{}, fmt.Errorf("encode run seal: %w", err)
	}
	if err := writeAtomicExclusive(filepath.Join(w.dir, "seal.json"), append(encoded, '\n')); err != nil {
		return RunSeal{}, fmt.Errorf("write run seal: %w", err)
	}
	if err := syncDirectory(w.dir); err != nil {
		return seal, fmt.Errorf("%w: %v", ErrCommitIndeterminate, err)
	}
	return seal, nil
}

func (w *RunWriter) closeStreams() error {
	var closeErr error
	for _, stream := range []*streamWriter{&w.public, &w.truth, &w.decisions} {
		if stream.file != nil {
			if err := stream.file.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
			stream.file = nil
		}
	}
	return closeErr
}

func (s *RunStore) Verify(id RunID) (RunSeal, error) {
	verified, err := s.verify(id, false)
	return verified.Seal, err
}

func (s *RunStore) ReadVerifiedRun(id RunID) (VerifiedRun, error) {
	return s.verify(id, true)
}

func (s *RunStore) verify(id RunID, collect bool) (VerifiedRun, error) {
	if s == nil {
		return VerifiedRun{}, errors.New("run store is nil")
	}
	if _, err := ParseRunID(string(id)); err != nil {
		return VerifiedRun{}, err
	}
	dir := filepath.Join(s.root, string(id))
	sealPath := filepath.Join(dir, "seal.json")
	if _, err := os.Stat(sealPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifiedRun{}, ErrIncompleteRun
		}
		return VerifiedRun{}, err
	}
	var spec RunSpec
	if err := readCanonical(filepath.Join(dir, "spec.json"), &spec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VerifiedRun{}, fmt.Errorf("%w: missing run spec", ErrIntegrity)
		}
		return VerifiedRun{}, fmt.Errorf("%w: read run spec: %v", ErrIntegrity, err)
	}
	if err := spec.Validate(); err != nil || spec.RunID != id {
		return VerifiedRun{}, fmt.Errorf("%w: invalid run spec", ErrIntegrity)
	}
	var seal RunSeal
	if err := readCanonical(sealPath, &seal); err != nil {
		return VerifiedRun{}, fmt.Errorf("%w: read seal: %v", ErrIntegrity, err)
	}
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return VerifiedRun{}, fmt.Errorf("encode verified run spec: %w", err)
	}
	bundleDigest, err := spec.BehaviorBundle.Digest()
	if err != nil {
		return VerifiedRun{}, fmt.Errorf("%w: invalid behavior bundle", ErrIntegrity)
	}
	if seal.SpecDigest != digestBytes(specBytes) || seal.BehaviorBundleDigest != bundleDigest {
		return VerifiedRun{}, fmt.Errorf("%w: spec or behavior bundle digest mismatch", ErrIntegrity)
	}

	actorPolicies := make(map[ActorID]PolicyID, len(spec.Actors))
	for _, actor := range spec.Actors {
		actorPolicies[actor.ID] = actor.Policy.ID
	}
	publicHead, publicCount, publicEvents, err := verifyStream[PublicEvent](filepath.Join(dir, "public.jsonl"), func(event PublicEvent) error {
		if err := event.Validate(); err != nil {
			return err
		}
		if event.Tick > spec.Limits.MaxTicks || event.ActorID != "" && actorPolicies[event.ActorID] == "" {
			return fmt.Errorf("%w: public event exceeds run contract", ErrInvalidRecord)
		}
		return nil
	}, collect)
	if err != nil {
		return VerifiedRun{}, err
	}
	truthHead, truthCount, truthRecords, err := verifyStream[TruthRecord](filepath.Join(dir, "truth.jsonl"), func(record TruthRecord) error {
		if err := record.Validate(); err != nil {
			return err
		}
		if record.Tick > spec.Limits.MaxTicks || record.ActorID != "" && actorPolicies[record.ActorID] == "" {
			return fmt.Errorf("%w: truth record exceeds run contract", ErrInvalidRecord)
		}
		return nil
	}, collect)
	if err != nil {
		return VerifiedRun{}, err
	}
	type actorTick struct {
		actor ActorID
		tick  uint64
	}
	seenDecisions := make(map[actorTick]struct{})
	decisionHead, decisionCount, decisions, err := verifyStream[DecisionRecord](filepath.Join(dir, "decisions.jsonl"), func(record DecisionRecord) error {
		if err := record.Validate(); err != nil {
			return err
		}
		if policy, ok := actorPolicies[record.ActorID]; !ok || policy != record.PolicyID || record.Tick > spec.Limits.MaxTicks {
			return fmt.Errorf("%w: decision actor, policy, or tick does not match run spec", ErrInvalidRecord)
		}
		key := actorTick{actor: record.ActorID, tick: record.Tick}
		if _, exists := seenDecisions[key]; exists {
			return fmt.Errorf("%w: duplicate actor decision at tick %d", ErrInvalidRecord, record.Tick)
		}
		seenDecisions[key] = struct{}{}
		return nil
	}, collect)
	if err != nil {
		return VerifiedRun{}, err
	}
	verified := VerifiedRun{Spec: spec, Seal: seal, PublicEvents: publicEvents, TruthRecords: truthRecords, Decisions: decisions}
	if publicHead != seal.PublicHead || publicCount != seal.PublicCount || truthHead != seal.TruthHead || truthCount != seal.TruthCount || decisionHead != seal.DecisionHead || decisionCount != seal.DecisionCount {
		return VerifiedRun{}, fmt.Errorf("%w: stream head or count mismatch", ErrIntegrity)
	}
	if seal.Completed && decisionCount == 0 {
		return VerifiedRun{}, fmt.Errorf("%w: completed run has no decision trace", ErrIntegrity)
	}
	if !seal.Completed {
		return verified, ErrIncompleteRun
	}
	return verified, nil
}

func verifyStream[T any](path string, validate func(T) error, collect bool) (string, uint64, []T, error) {
	contents, err := readLimited(path, maxStreamBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", 0, nil, fmt.Errorf("%w: missing sealed stream %s", ErrIntegrity, filepath.Base(path))
		}
		if errors.Is(err, ErrFileTooLarge) {
			return "", 0, nil, fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
		return "", 0, nil, err
	}
	if len(contents) == 0 {
		return "", 0, nil, nil
	}
	if contents[len(contents)-1] != '\n' {
		return "", 0, nil, fmt.Errorf("%w: stream %s is truncated", ErrIntegrity, filepath.Base(path))
	}
	if bytes.Contains(contents, []byte{'\r'}) {
		return "", 0, nil, fmt.Errorf("%w: carriage returns in canonical stream", ErrIntegrity)
	}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 64*1024), maxStreamBytes)
	var head string
	var count uint64
	var records []T
	for scanner.Scan() {
		line := scanner.Bytes()
		var entry chainEnvelope
		if err := decodeStrict(line, &entry); err != nil {
			return "", 0, nil, fmt.Errorf("%w: decode %s entry: %v", ErrIntegrity, filepath.Base(path), err)
		}
		canonicalEntry, err := json.Marshal(entry)
		if err != nil || !bytes.Equal(canonicalEntry, line) {
			return "", 0, nil, fmt.Errorf("%w: non-canonical %s entry", ErrIntegrity, filepath.Base(path))
		}
		if entry.Sequence != count+1 || entry.PreviousHash != head || len(entry.Payload) == 0 {
			return "", 0, nil, fmt.Errorf("%w: broken sequence in %s", ErrIntegrity, filepath.Base(path))
		}
		var payload T
		if err := decodeStrict(entry.Payload, &payload); err != nil {
			return "", 0, nil, fmt.Errorf("%w: decode %s payload: %v", ErrIntegrity, filepath.Base(path), err)
		}
		canonicalPayload, err := json.Marshal(payload)
		if err != nil || !bytes.Equal(canonicalPayload, entry.Payload) {
			return "", 0, nil, fmt.Errorf("%w: non-canonical %s payload", ErrIntegrity, filepath.Base(path))
		}
		if err := validate(payload); err != nil {
			return "", 0, nil, fmt.Errorf("%w: invalid %s payload: %v", ErrIntegrity, filepath.Base(path), err)
		}
		body := chainBody{Sequence: entry.Sequence, PreviousHash: entry.PreviousHash, Payload: entry.Payload}
		encodedBody, err := json.Marshal(body)
		if err != nil || digestBytes(encodedBody) != entry.Hash {
			return "", 0, nil, fmt.Errorf("%w: hash mismatch in %s", ErrIntegrity, filepath.Base(path))
		}
		head = entry.Hash
		count++
		if collect {
			records = append(records, payload)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, nil, fmt.Errorf("%w: read %s: %v", ErrIntegrity, filepath.Base(path), err)
	}
	return head, count, records, nil
}

func (e PublicEvent) Validate() error {
	if !utf8.ValidString(e.Path) || !utf8.ValidString(e.ArtifactID) || !utf8.ValidString(string(e.Recipient)) || !utf8.ValidString(e.Message) || !utf8.ValidString(e.ReasonCode) {
		return fmt.Errorf("%w: public event contains invalid UTF-8", ErrInvalidRecord)
	}
	if !validToken(e.Kind, 96) || !validToken(e.Outcome, 96) {
		return fmt.Errorf("%w: invalid public event kind or outcome", ErrInvalidRecord)
	}
	if e.ActorID != "" && !validToken(string(e.ActorID), 96) {
		return fmt.Errorf("%w: invalid public event actor", ErrInvalidRecord)
	}
	if e.Recipient != "" && !validToken(string(e.Recipient), 96) || e.ArtifactID != "" && !validToken(e.ArtifactID, 96) || e.ReasonCode != "" && !validToken(e.ReasonCode, 96) {
		return fmt.Errorf("%w: invalid public event identity or reason code", ErrInvalidRecord)
	}
	if e.IntentKind != "" && !validIntentKind(e.IntentKind) {
		return fmt.Errorf("%w: invalid public event intent kind", ErrInvalidRecord)
	}
	if e.ContentDigest != "" && !isDigest(e.ContentDigest) {
		return fmt.Errorf("%w: invalid public content digest", ErrInvalidRecord)
	}
	return nil
}

func (r TruthRecord) Validate() error {
	if !utf8.ValidString(r.ArtifactID) || r.ArtifactID != "" && !validToken(r.ArtifactID, 96) {
		return fmt.Errorf("%w: truth record contains invalid UTF-8", ErrInvalidRecord)
	}
	if !validToken(r.FactKind, 96) || r.ActorID != "" && !validToken(string(r.ActorID), 96) {
		return fmt.Errorf("%w: invalid truth record", ErrInvalidRecord)
	}
	if r.ExpectedDigest != "" && !isDigest(r.ExpectedDigest) || r.ActualDigest != "" && !isDigest(r.ActualDigest) {
		return fmt.Errorf("%w: invalid truth digest", ErrInvalidRecord)
	}
	return nil
}

func (o MonitorObservation) Validate() error {
	if !utf8.ValidString(o.Resource) || !utf8.ValidString(o.ReasonCode) {
		return fmt.Errorf("%w: monitor observation contains invalid UTF-8", ErrInvalidRecord)
	}
	if o.Sequence == 0 || !validToken(o.EventKind, 96) || !validToken(o.Outcome, 96) {
		return fmt.Errorf("%w: invalid monitor observation", ErrInvalidRecord)
	}
	if o.ActorID != "" && !validToken(string(o.ActorID), 96) {
		return fmt.Errorf("%w: invalid monitor actor", ErrInvalidRecord)
	}
	if o.ReasonCode != "" && !validToken(o.ReasonCode, 96) {
		return fmt.Errorf("%w: invalid monitor reason code", ErrInvalidRecord)
	}
	if o.IntentKind != "" && !validIntentKind(o.IntentKind) {
		return fmt.Errorf("%w: invalid monitor intent kind", ErrInvalidRecord)
	}
	if o.ContentDigest != "" && !isDigest(o.ContentDigest) {
		return fmt.Errorf("%w: invalid monitor content digest", ErrInvalidRecord)
	}
	return nil
}

func validIntentKind(kind IntentKind) bool {
	switch kind {
	case IntentInspect, IntentEdit, IntentRunVerification, IntentSendMessage, IntentShareArtifact, IntentRequestCapability, IntentSubmit, IntentAbstain:
		return true
	default:
		return false
	}
}

func readCanonical(path string, target any) error {
	contents, err := readLimited(path, maxSpecBytes)
	if err != nil {
		return err
	}
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		return errors.New("missing canonical newline")
	}
	body := contents[:len(contents)-1]
	if err := decodeStrict(body, target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, body) {
		return errors.New("JSON is not canonical")
	}
	return nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, ErrFileTooLarge
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, ErrFileTooLarge
	}
	return contents, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeFull(file, data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeAtomicExclusive(path string, data []byte) error {
	temporary := path + ".tmp"
	if err := writeExclusive(temporary, data); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	_ = os.Remove(temporary)
	return nil
}

func writeFull(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func syncDirectoryChain(path string) error {
	current := filepath.Clean(path)
	for {
		if err := syncDirectory(current); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}
