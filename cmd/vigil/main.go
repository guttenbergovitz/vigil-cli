package main

import (
	"fmt"
	"os"

	"github.com/guttenbergovitz/vigil-cli/internal/cli"
	"github.com/guttenbergovitz/vigil-cli/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: vigil <command> [args]")
	}

	cmd := os.Args[1]

	switch cmd {
	case "scan":
		return cli.Scan(os.Args[2:])
	case "report":
		return cli.Report(os.Args[2:])
	case "ci":
		return cli.CI(os.Args[2:])
	case "version":
		fmt.Printf("vigil %s\n", version.GetFull())
		return nil
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}
