package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/observatory"
)

const usage = `Usage: observatory <command> [flags]

Commands:
  fixtures  list registered benchmark fixtures
  run       run one fixture under a topology
  inspect   show bounded public and monitor events from a verified run
  verify    verify a stored run's integrity seal
  replay    replay a run with the exact supported behavior bundle
  evaluate  score a complete, integrity-verified run
  regress   execute the versioned incident regression corpus
`

var errHelpRequested = errors.New("help requested")

func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(stdout, usage)
		return err
	}
	var err error
	switch args[0] {
	case "fixtures":
		err = fixturesCommand(args[1:], stdout, stderr)
	case "run":
		err = runCommand(args[1:], stdout, stderr)
	case "inspect":
		err = inspectCommand(args[1:], stdout, stderr)
	case "verify":
		err = verifyCommand(args[1:], stdout, stderr)
	case "replay":
		err = replayCommand(args[1:], stdout, stderr)
	case "evaluate":
		err = evaluateCommand(args[1:], stdout, stderr)
	case "regress":
		err = regressCommand(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	return err
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func parseFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelpRequested
		}
		return err
	}
	return nil
}

func requireNoPositionals(flags *flag.FlagSet) error {
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	return nil
}

func parseTopology(value string) (observatory.Topology, error) {
	switch observatory.Topology(value) {
	case observatory.TopologySharedMessages, observatory.TopologyHierarchical:
		return observatory.Topology(value), nil
	default:
		return "", fmt.Errorf("unsupported topology %q (use shared_messages or hierarchical)", value)
	}
}

func tailPublic(records []observatory.PublicEvent, limit int) []observatory.PublicEvent {
	if len(records) > limit {
		records = records[len(records)-limit:]
	}
	return records
}

func tailMonitor(records []observatory.MonitorRecord, limit int) []observatory.MonitorRecord {
	if len(records) > limit {
		records = records[len(records)-limit:]
	}
	return records
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON output: %w", err)
	}
	return nil
}
