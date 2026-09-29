package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/benchmark"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/policy"
)

const (
	maxUIRequestBytes = 64 << 10
	maxUISessions     = 128
	maxUIRecords      = 500
)

//go:embed ui/static/*
var uiAssets embed.FS

type uiSession struct {
	token    string
	lastSeen time.Time
}

type uiSessions struct {
	mu   sync.Mutex
	byID map[string]uiSession
	now  func() time.Time
}

type uiServer struct {
	store          *observatory.RunStore
	repositoryRoot string
	host           string
	sessions       *uiSessions
	mux            *http.ServeMux
}

type createRunRequest struct {
	Fixture      benchmark.FixtureID `json:"fixture"`
	Topology     string              `json:"topology"`
	WorkerPolicy string              `json:"worker_policy"`
}

type replayRequest struct{}

type runDetail struct {
	RunID             observatory.RunID           `json:"run_id"`
	ScenarioID        string                      `json:"scenario_id"`
	Topology          observatory.Topology        `json:"topology"`
	Completed         bool                        `json:"completed"`
	IntegrityVerified bool                        `json:"integrity_verified"`
	PublicTotal       uint64                      `json:"public_total"`
	PublicEvents      []observatory.PublicEvent   `json:"public_events"`
	MonitorTotal      uint64                      `json:"monitor_total"`
	MonitorRecords    []observatory.MonitorRecord `json:"monitor_records"`
	Truncated         bool                        `json:"truncated"`
}

func uiCommand(args []string, stderr io.Writer) error {
	flags := newFlags("ui", stderr)
	port := flags.Int("port", 8765, "TCP port (0 chooses an available local port)")
	storePath := flags.String("store", ".observatory/runs", "run evidence directory")
	repositoryRoot := flags.String("repo", ".", "repository root containing the bundled Python policy")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireNoPositionals(flags); err != nil {
		return err
	}
	if *port < 0 || *port > 65535 {
		return errors.New("--port must be between 0 and 65535")
	}
	root, err := findRepositoryRoot(*repositoryRoot)
	if err != nil {
		return err
	}
	store, err := openStore(*storePath)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return fmt.Errorf("listen on loopback; choose another --port if occupied: %w", err)
	}
	defer listener.Close()
	host := listener.Addr().String()
	server := &http.Server{Handler: newUIHandler(store, root, host), ReadHeaderTimeout: 5 * time.Second}
	if _, err := fmt.Fprintf(stderr, "Observatory UI: http://%s\n", host); err != nil {
		return err
	}
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve loopback UI: %w", err)
}

func newUIHandler(store *observatory.RunStore, repositoryRoot, host string) http.Handler {
	server := &uiServer{
		store: store, repositoryRoot: repositoryRoot, host: host,
		sessions: &uiSessions{byID: make(map[string]uiSession), now: time.Now},
		mux:      http.NewServeMux(),
	}
	server.mux.HandleFunc("GET /", server.handleIndex)
	server.mux.HandleFunc("GET /ui.css", server.handleAsset("ui/static/ui.css", "text/css; charset=utf-8"))
	server.mux.HandleFunc("GET /ui.js", server.handleAsset("ui/static/ui.js", "text/javascript; charset=utf-8"))
	server.mux.HandleFunc("GET /api/session", server.handleSession)
	server.mux.HandleFunc("GET /api/fixtures", server.handleFixtures)
	server.mux.HandleFunc("GET /api/runs", methodNotAllowed("run creation requires POST"))
	server.mux.HandleFunc("POST /api/runs", server.handleCreateRun)
	server.mux.HandleFunc("GET /api/runs/{id}", server.handleRun)
	server.mux.HandleFunc("GET /api/runs/{id}/verify", server.handleVerifyRun)
	server.mux.HandleFunc("GET /api/runs/{id}/evaluation", server.handleEvaluation)
	server.mux.HandleFunc("GET /api/runs/{id}/truth", server.handleTruthProjection)
	server.mux.HandleFunc("GET /api/runs/{id}/replay", methodNotAllowed("replay requires POST"))
	server.mux.HandleFunc("POST /api/runs/{id}/replay", server.handleReplay)
	return server
}

func (s *uiServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if request.Host != s.host {
		writeAPIError(writer, http.StatusForbidden, "request Host does not match this loopback server")
		return
	}
	s.mux.ServeHTTP(writer, request)
}

func (s *uiServer) handleIndex(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	s.serveAsset(writer, "ui/static/index.html", "text/html; charset=utf-8")
}

func methodNotAllowed(message string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writeAPIError(writer, http.StatusMethodNotAllowed, message)
	}
}

func (s *uiServer) handleAsset(name, contentType string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		s.serveAsset(writer, name, contentType)
	}
}

func (s *uiServer) serveAsset(writer http.ResponseWriter, name, contentType string) {
	content, err := uiAssets.ReadFile(name)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "UI asset is unavailable")
		return
	}
	writer.Header().Set("Content-Type", contentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(content)
}

func (s *uiServer) handleSession(writer http.ResponseWriter, request *http.Request) {
	sessionID, session, found := s.sessions.get(request)
	if !found {
		var err error
		sessionID, session, err = s.sessions.create()
		if err != nil {
			writeAPIError(writer, http.StatusInternalServerError, "could not create a browser session")
			return
		}
		http.SetCookie(writer, &http.Cookie{
			Name: "observatory_session", Value: sessionID, Path: "/", HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	_ = s.sessions.touch(sessionID)
	writeJSONStatus(writer, http.StatusOK, struct {
		CSRFToken string `json:"csrf_token"`
	}{session.token})
}

func (s *uiSessions) get(request *http.Request) (string, uiSession, bool) {
	cookie, err := request.Cookie("observatory_session")
	if err != nil || cookie.Value == "" {
		return "", uiSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byID[cookie.Value]
	if !ok || s.now().Sub(session.lastSeen) > 12*time.Hour {
		delete(s.byID, cookie.Value)
		return "", uiSession{}, false
	}
	return cookie.Value, session, true
}

func (s *uiSessions) touch(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byID[id]
	if !ok {
		return false
	}
	session.lastSeen = s.now()
	s.byID[id] = session
	return true
}

func (s *uiSessions) create() (string, uiSession, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", uiSession{}, err
	}
	var csrf [32]byte
	if _, err := rand.Read(csrf[:]); err != nil {
		return "", uiSession{}, err
	}
	id, token := hex.EncodeToString(raw[:]), hex.EncodeToString(csrf[:])
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, session := range s.byID {
		if now.Sub(session.lastSeen) > 12*time.Hour {
			delete(s.byID, key)
		}
	}
	if len(s.byID) >= maxUISessions {
		oldestID := ""
		var oldest time.Time
		for key, session := range s.byID {
			if oldestID == "" || session.lastSeen.Before(oldest) {
				oldestID, oldest = key, session.lastSeen
			}
		}
		delete(s.byID, oldestID)
	}
	session := uiSession{token: token, lastSeen: now}
	s.byID[id] = session
	return id, session, nil
}

func (s *uiServer) handleFixtures(writer http.ResponseWriter, _ *http.Request) {
	writeJSONStatus(writer, http.StatusOK, struct {
		SchemaVersion string                        `json:"schema_version"`
		Fixtures      []benchmark.FixtureDefinition `json:"fixtures"`
	}{"fixture-catalog-v1", benchmark.FixtureCatalog()})
}

func (s *uiServer) handleCreateRun(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeMutation(writer, request) {
		return
	}
	var input createRunRequest
	if !decodeJSONBody(writer, request, &input) {
		return
	}
	if input.Fixture == "" {
		writeAPIError(writer, http.StatusBadRequest, "fixture is required")
		return
	}
	if input.WorkerPolicy == "" {
		input.WorkerPolicy = string(policy.HonestRepair)
	}
	task, err := benchmark.NewFixtureTask(input.Fixture)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "unknown fixture; refresh the fixture list")
		return
	}
	topology, err := parseTopology(input.Topology)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err.Error())
		return
	}
	actors, policies, err := pythonPolicies(s.repositoryRoot, input.WorkerPolicy)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err.Error())
		return
	}
	build, err := buildDigest()
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "cannot establish the current behavior build identity")
		return
	}
	monitor := observatory.DefaultRuleMonitor()
	environment, err := newRunEnvironment(s.store, task, topology, actors, policies, monitor, build)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "cannot prepare fixture run: "+err.Error())
		return
	}
	result, err := environment.engine.Run(request.Context(), environment.spec)
	if err != nil {
		writeAPIError(writer, http.StatusUnprocessableEntity, "fixture run failed: "+err.Error())
		return
	}
	detail, err := s.loadRunDetail(result.RunID)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "run completed but its verified report could not be read")
		return
	}
	writeJSONStatus(writer, http.StatusCreated, detail)
}

func (s *uiServer) handleRun(writer http.ResponseWriter, request *http.Request) {
	runID, ok := s.pathRunID(writer, request)
	if !ok {
		return
	}
	detail, err := s.loadRunDetail(runID)
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, "run is missing, incomplete, or failed integrity verification")
		return
	}
	writeJSONStatus(writer, http.StatusOK, detail)
}

func (s *uiServer) loadRunDetail(runID observatory.RunID) (runDetail, error) {
	run, err := s.store.ReadVerifiedRun(runID)
	if err != nil {
		return runDetail{}, err
	}
	if !run.Seal.Completed {
		return runDetail{}, observatory.ErrIncompleteRun
	}
	publicStart := max(0, len(run.PublicEvents)-maxUIRecords)
	monitorStart := max(0, len(run.MonitorRecords)-maxUIRecords)
	return runDetail{
		RunID: runID, ScenarioID: run.Spec.ScenarioID, Topology: run.Spec.Topology,
		Completed: true, IntegrityVerified: true,
		PublicTotal: run.Seal.PublicCount, PublicEvents: run.PublicEvents[publicStart:],
		MonitorTotal: run.Seal.MonitorCount, MonitorRecords: run.MonitorRecords[monitorStart:],
		Truncated: publicStart > 0 || monitorStart > 0,
	}, nil
}

func (s *uiServer) handleVerifyRun(writer http.ResponseWriter, request *http.Request) {
	runID, ok := s.pathRunID(writer, request)
	if !ok {
		return
	}
	seal, err := s.store.Verify(runID)
	if err != nil || !seal.Completed {
		writeAPIError(writer, http.StatusUnprocessableEntity, "run is incomplete or failed integrity verification")
		return
	}
	writeJSONStatus(writer, http.StatusOK, struct {
		RunID         observatory.RunID `json:"run_id"`
		Verified      bool              `json:"verified"`
		Completed     bool              `json:"completed"`
		PublicCount   uint64            `json:"public_count"`
		DecisionCount uint64            `json:"decision_count"`
		MonitorCount  uint64            `json:"monitor_count"`
	}{runID, true, true, seal.PublicCount, seal.DecisionCount, seal.MonitorCount})
}

func (s *uiServer) handleEvaluation(writer http.ResponseWriter, request *http.Request) {
	runID, ok := s.pathRunID(writer, request)
	if !ok {
		return
	}
	run, err := s.store.ReadVerifiedRun(runID)
	if err != nil || !run.Seal.Completed {
		writeAPIError(writer, http.StatusUnprocessableEntity, "evaluation is available only for complete, integrity-verified runs")
		return
	}
	task, err := taskForScenario(run.Spec.ScenarioID)
	if err != nil {
		writeAPIError(writer, http.StatusUnprocessableEntity, "run scenario has no registered evaluator")
		return
	}
	report, err := benchmark.EvaluateRun(s.store, runID, task)
	if err != nil {
		writeAPIError(writer, http.StatusUnprocessableEntity, "evaluation failed: "+err.Error())
		return
	}
	writeJSONStatus(writer, http.StatusOK, report)
}

func (s *uiServer) handleTruthProjection(writer http.ResponseWriter, request *http.Request) {
	runID, ok := s.pathRunID(writer, request)
	if !ok {
		return
	}
	run, err := s.store.ReadVerifiedRun(runID)
	if err != nil || !run.Seal.Completed {
		writeAPIError(writer, http.StatusUnprocessableEntity, "evaluator truth is hidden until the complete run passes integrity verification")
		return
	}
	writeJSONStatus(writer, http.StatusOK, struct {
		RunID        observatory.RunID         `json:"run_id"`
		Verified     bool                      `json:"verified"`
		Completed    bool                      `json:"completed"`
		TruthRecords []observatory.TruthRecord `json:"truth_records"`
	}{runID, true, true, run.TruthRecords})
}

func (s *uiServer) handleReplay(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeMutation(writer, request) {
		return
	}
	var input replayRequest
	if !decodeJSONBody(writer, request, &input) {
		return
	}
	runID, ok := s.pathRunID(writer, request)
	if !ok {
		return
	}
	source, err := s.store.ReadVerifiedRun(runID)
	if err != nil || !source.Seal.Completed {
		writeAPIError(writer, http.StatusUnprocessableEntity, "refusing to replay an incomplete or integrity-invalid source run")
		return
	}
	build, err := buildDigest()
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "cannot establish the current behavior build identity")
		return
	}
	engine, err := replayEngine(s.store, source, build)
	if err != nil {
		writeAPIError(writer, http.StatusUnprocessableEntity, err.Error())
		return
	}
	replayID, err := newRunID("replay")
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "could not create a replay run ID")
		return
	}
	result, err := engine.Replay(request.Context(), runID, replayID)
	if err != nil {
		writeAPIError(writer, http.StatusUnprocessableEntity, "replay failed; no faithful result was established: "+err.Error())
		return
	}
	detail, err := s.loadRunDetail(result.RunID)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "replay completed but its verified report could not be read")
		return
	}
	writeJSONStatus(writer, http.StatusCreated, struct {
		Faithful    bool              `json:"faithful"`
		SourceRunID observatory.RunID `json:"source_run_id"`
		Replay      runDetail         `json:"replay"`
	}{true, runID, detail})
}

func (s *uiServer) pathRunID(writer http.ResponseWriter, request *http.Request) (observatory.RunID, bool) {
	runID, err := observatory.ParseRunID(request.PathValue("id"))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid run ID")
		return "", false
	}
	return runID, true
}

func (s *uiServer) authorizeMutation(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodPost {
		writeAPIError(writer, http.StatusMethodNotAllowed, "mutations require POST")
		return false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "mutations require Content-Type: application/json")
		return false
	}
	origin, err := url.Parse(request.Header.Get("Origin"))
	if err != nil || origin.Scheme != "http" || origin.Host != s.host || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		writeAPIError(writer, http.StatusForbidden, "mutation Origin must exactly match this loopback UI")
		return false
	}
	cookie, err := request.Cookie("observatory_session")
	if err != nil || cookie.Value == "" {
		writeAPIError(writer, http.StatusForbidden, "mutation requires a browser session")
		return false
	}
	s.sessions.mu.Lock()
	session, exists := s.sessions.byID[cookie.Value]
	if exists && s.sessions.now().Sub(session.lastSeen) <= 12*time.Hour {
		session.lastSeen = s.sessions.now()
		s.sessions.byID[cookie.Value] = session
	} else {
		delete(s.sessions.byID, cookie.Value)
		exists = false
	}
	s.sessions.mu.Unlock()
	provided := request.Header.Get("X-CSRF-Token")
	if !exists || len(provided) != len(session.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(session.token)) != 1 {
		writeAPIError(writer, http.StatusForbidden, "mutation CSRF token is missing or invalid")
		return false
	}
	return true
}

func decodeJSONBody(writer http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maxUIRequestBytes)
	contents, err := io.ReadAll(request.Body)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "could not read JSON request")
		return false
	}
	trimmed := bytes.TrimSpace(contents)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		writeAPIError(writer, http.StatusBadRequest, "request body must be one JSON object")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid JSON request: "+err.Error())
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeAPIError(writer, http.StatusBadRequest, "request must contain exactly one JSON value")
		return false
	}
	return true
}

func writeAPIError(writer http.ResponseWriter, status int, message string) {
	writeJSONStatus(writer, status, struct {
		Error string `json:"error"`
	}{message})
}

func writeJSONStatus(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
