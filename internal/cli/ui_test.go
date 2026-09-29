package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/benchmark"
	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

const testUIHost = "127.0.0.1:8765"

type browserSession struct {
	token  string
	cookie *http.Cookie
}

func TestUIMutationRequestsRequireExactHostOriginJSONAndCSRF(t *testing.T) {
	handler, storePath := testUIHandler(t)
	session := createBrowserSession(t, handler, testUIHost)
	body := []byte(`{"fixture":"honest-coordination","topology":"shared_messages","worker_policy":"honest_repair"}`)
	validOrigin := "http://" + testUIHost
	tests := []struct {
		name        string
		host        string
		origin      string
		contentType string
		token       string
		method      string
		body        []byte
		wantStatus  int
	}{
		{name: "wrong host", host: "127.0.0.1:8766", origin: validOrigin, contentType: "application/json", token: session.token, method: http.MethodPost, body: body, wantStatus: http.StatusForbidden},
		{name: "cross origin", host: testUIHost, origin: "http://attacker.example", contentType: "application/json", token: session.token, method: http.MethodPost, body: body, wantStatus: http.StatusForbidden},
		{name: "origin path", host: testUIHost, origin: validOrigin + "/", contentType: "application/json", token: session.token, method: http.MethodPost, body: body, wantStatus: http.StatusForbidden},
		{name: "missing csrf", host: testUIHost, origin: validOrigin, contentType: "application/json", method: http.MethodPost, body: body, wantStatus: http.StatusForbidden},
		{name: "wrong content type", host: testUIHost, origin: validOrigin, contentType: "text/plain", token: session.token, method: http.MethodPost, body: body, wantStatus: http.StatusUnsupportedMediaType},
		{name: "get cannot mutate", host: testUIHost, origin: validOrigin, contentType: "application/json", token: session.token, method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		{name: "json object required", host: testUIHost, origin: validOrigin, contentType: "application/json", token: session.token, method: http.MethodPost, body: []byte("null"), wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := callUI(handler, test.method, "/api/runs", test.host, test.origin, test.contentType, test.token, session.cookie, test.body)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
	entries, err := os.ReadDir(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected mutations created run data: %v", entries)
	}
	fixtures := callUI(handler, http.MethodGet, "/api/fixtures", testUIHost, "http://attacker.example", "", "", nil, nil)
	if fixtures.Code != http.StatusOK || fixtures.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("read-only cross-origin request unexpectedly failed or enabled CORS: status=%d", fixtures.Code)
	}
}

func TestUISessionsHaveIndependentTokens(t *testing.T) {
	handler, _ := testUIHandler(t)
	first := createBrowserSession(t, handler, testUIHost)
	second := createBrowserSession(t, handler, testUIHost)
	if first.token == second.token || first.cookie.Value == second.cookie.Value {
		t.Fatal("separate browser sessions reused a session identifier or CSRF token")
	}
	response := callUI(handler, http.MethodGet, "/api/session", testUIHost, "", "", "", first.cookie, nil)
	var payload struct {
		Token string `json:"csrf_token"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &payload) != nil || payload.Token != first.token {
		t.Fatalf("existing browser session did not retain its token: %d %s", response.Code, response.Body.String())
	}
}

func TestUIRunEvaluationTruthAndReplayWorkflow(t *testing.T) {
	handler, _ := testUIHandler(t)
	session := createBrowserSession(t, handler, testUIHost)
	detail := startUIRun(t, handler, session, testUIHost)
	if !detail.Completed || !detail.IntegrityVerified || detail.Topology != observatory.TopologyHierarchical {
		t.Fatalf("run response did not prove a verified completion: %#v", detail)
	}
	encodedDetail, _ := json.Marshal(detail)
	if bytes.Contains(encodedDetail, []byte("truth_records")) || bytes.Contains(encodedDetail, []byte("expected_digest")) || bytes.Contains(encodedDetail, []byte("actual_digest")) {
		t.Fatalf("default run projection exposed evaluator truth: %s", encodedDetail)
	}

	verify := callUI(handler, http.MethodGet, "/api/runs/"+string(detail.RunID)+"/verify", testUIHost, "", "", "", nil, nil)
	if verify.Code != http.StatusOK || bytes.Contains(verify.Body.Bytes(), []byte("truth_count")) {
		t.Fatalf("integrity endpoint failed or exposed truth metadata: %d %s", verify.Code, verify.Body.String())
	}
	evaluation := callUI(handler, http.MethodGet, "/api/runs/"+string(detail.RunID)+"/evaluation", testUIHost, "", "", "", nil, nil)
	var report benchmark.EvaluationReport
	if evaluation.Code != http.StatusOK || json.Unmarshal(evaluation.Body.Bytes(), &report) != nil || !report.EvidenceIntegrity.Verified || !report.Metrics.TaskQuality.Mergeable {
		t.Fatalf("evaluation endpoint failed: %d %s", evaluation.Code, evaluation.Body.String())
	}
	truth := callUI(handler, http.MethodGet, "/api/runs/"+string(detail.RunID)+"/truth", testUIHost, "", "", "", nil, nil)
	var projection struct {
		Verified bool                      `json:"verified"`
		Complete bool                      `json:"completed"`
		Records  []observatory.TruthRecord `json:"truth_records"`
	}
	if truth.Code != http.StatusOK || json.Unmarshal(truth.Body.Bytes(), &projection) != nil || !projection.Verified || !projection.Complete || len(projection.Records) == 0 {
		t.Fatalf("explicit truth projection was not available after verification: %d %s", truth.Code, truth.Body.String())
	}

	replay := callUI(handler, http.MethodPost, "/api/runs/"+string(detail.RunID)+"/replay", testUIHost, "http://"+testUIHost, "application/json", session.token, session.cookie, []byte(`{}`))
	var replayResult struct {
		Faithful bool      `json:"faithful"`
		Replay   runDetail `json:"replay"`
	}
	if replay.Code != http.StatusCreated || json.Unmarshal(replay.Body.Bytes(), &replayResult) != nil || !replayResult.Faithful || !replayResult.Replay.IntegrityVerified {
		t.Fatalf("verified replay failed: %d %s", replay.Code, replay.Body.String())
	}
}

func TestUITruthAndReplayRejectIncompleteOrTamperedEvidence(t *testing.T) {
	handler, storePath := testUIHandler(t)
	session := createBrowserSession(t, handler, testUIHost)
	store, err := observatory.NewRunStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	task, err := benchmark.NewFixtureTask(benchmark.FixtureHonestCoordination)
	if err != nil {
		t.Fatal(err)
	}
	actors, policies, err := demoPolicies("honest")
	if err != nil {
		t.Fatal(err)
	}
	build, err := buildDigest()
	if err != nil {
		t.Fatal(err)
	}
	monitor := observatory.DefaultRuleMonitor()
	environment, err := newRunEnvironment(store, task, observatory.TopologySharedMessages, actors, policies, monitor, build)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Reserve(environment.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Finalize(false); err != nil {
		t.Fatal(err)
	}
	incompleteTruth := callUI(handler, http.MethodGet, "/api/runs/"+string(environment.spec.RunID)+"/truth", testUIHost, "", "", "", nil, nil)
	if incompleteTruth.Code != http.StatusUnprocessableEntity || bytes.Contains(incompleteTruth.Body.Bytes(), []byte("truth_records")) {
		t.Fatalf("incomplete run exposed truth: %d %s", incompleteTruth.Code, incompleteTruth.Body.String())
	}

	detail := startUIRun(t, handler, session, testUIHost)
	if err := corruptPublicStream(storePath, detail.RunID); err != nil {
		t.Fatal(err)
	}
	tamperedTruth := callUI(handler, http.MethodGet, "/api/runs/"+string(detail.RunID)+"/truth", testUIHost, "", "", "", nil, nil)
	if tamperedTruth.Code != http.StatusUnprocessableEntity || bytes.Contains(tamperedTruth.Body.Bytes(), []byte("truth_records")) {
		t.Fatalf("tampered run exposed truth: %d %s", tamperedTruth.Code, tamperedTruth.Body.String())
	}
	tamperedReplay := callUI(handler, http.MethodPost, "/api/runs/"+string(detail.RunID)+"/replay", testUIHost, "http://"+testUIHost, "application/json", session.token, session.cookie, []byte(`{}`))
	if tamperedReplay.Code != http.StatusUnprocessableEntity || bytes.Contains(tamperedReplay.Body.Bytes(), []byte(`"faithful":true`)) {
		t.Fatalf("tampered run was replayed or claimed faithful: %d %s", tamperedReplay.Code, tamperedReplay.Body.String())
	}
}

func TestUIEmbedsLocalAssetsAndSecurityHeaders(t *testing.T) {
	handler, _ := testUIHandler(t)
	response := callUI(handler, http.MethodGet, "/", testUIHost, "", "", "", nil, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("local page did not load with restrictive policy: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "https://") || !strings.Contains(response.Body.String(), "/ui.js") {
		t.Fatalf("page references remote resources or omitted its local app bundle")
	}
	asset := callUI(handler, http.MethodGet, "/ui.js", testUIHost, "", "", "", nil, nil)
	if asset.Code != http.StatusOK || strings.Contains(asset.Body.String(), "https://") {
		t.Fatalf("app script is missing or uses remote requests: %d", asset.Code)
	}
}

func testUIHandler(t *testing.T) (http.Handler, string) {
	t.Helper()
	storePath := filepath.Join(t.TempDir(), "runs")
	store, err := observatory.NewRunStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	return newUIHandler(store, repositoryRoot(t), testUIHost), storePath
}

func createBrowserSession(t *testing.T, handler http.Handler, host string) browserSession {
	t.Helper()
	response := callUI(handler, http.MethodGet, "/api/session", host, "", "", "", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("session bootstrap failed: %d %s", response.Code, response.Body.String())
	}
	var payload struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if payload.Token == "" || len(cookies) != 1 || cookies[0].Name != "observatory_session" || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session bootstrap omitted secure session material: token=%t cookies=%#v", payload.Token != "", cookies)
	}
	return browserSession{token: payload.Token, cookie: cookies[0]}
}

func callUI(handler http.Handler, method, path, host, origin, contentType, csrf string, cookie *http.Cookie, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://"+host+path, bytes.NewReader(body))
	request.Host = host
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	if cookie != nil {
		request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func startUIRun(t *testing.T, handler http.Handler, session browserSession, host string) runDetail {
	t.Helper()
	body := []byte(`{"fixture":"honest-coordination","topology":"hierarchical","worker_policy":"honest_repair"}`)
	response := callUI(handler, http.MethodPost, "/api/runs", host, "http://"+host, "application/json", session.token, session.cookie, body)
	if response.Code != http.StatusCreated {
		t.Fatalf("create run: %d %s", response.Code, response.Body.String())
	}
	var detail runDetail
	if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	return detail
}
