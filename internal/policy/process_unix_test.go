//go:build unix

package policy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

func TestProcessGroupHelper(t *testing.T) {
	switch os.Getenv("OBSERVATORY_PROCESS_HELPER") {
	case "child":
		time.Sleep(700 * time.Millisecond)
		if err := os.WriteFile(os.Getenv("OBSERVATORY_MARKER"), []byte("survived"), 0o600); err != nil {
			os.Exit(2)
		}
		return
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestProcessGroupHelper$")
		child.Env = replaceEnv(os.Environ(), "OBSERVATORY_PROCESS_HELPER", "child")
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		time.Sleep(10 * time.Second)
		return
	default:
		return
	}
}

func TestTimeoutKillsPolicyProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "child-survived")
	command := exec.Command(os.Args[0], "-test.run=^TestProcessGroupHelper$")
	command.Env = replaceEnv(os.Environ(), "OBSERVATORY_PROCESS_HELPER", "parent")
	command.Env = replaceEnv(command.Env, "OBSERVATORY_MARKER", marker)
	limits := DefaultLimits()
	limits.Timeout = 150 * time.Millisecond
	started := time.Now()
	_, err := runBoundedCommand(context.Background(), command, nil, limits)
	if err == nil {
		t.Fatal("timed out command unexpectedly succeeded")
	}
	var failure observatory.PolicyFailure
	if !errors.As(err, &failure) {
		t.Fatalf("timeout returned %T %v, expected a normalized policy failure", err, err)
	}
	if got := failure.Code; got != "timeout" {
		t.Fatalf("timeout failure code = %q", got)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("process group did not terminate promptly: %s", elapsed)
	}
	time.Sleep(900 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("policy descendant survived process-group timeout; marker stat error=%v", err)
	}
}

func replaceEnv(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}
