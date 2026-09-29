package main

import (
	"fmt"
	"os"

	"github.com/jpequegn/agent-swarm-collusion-observatory/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}
