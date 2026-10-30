// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type options struct {
	adapter  string
	snapshot string
	workDir  string
}

func parseOptions(args []string) (options, error) {
	var selected options
	flags := flag.NewFlagSet("sdk-consumer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&selected.adapter, "adapter", "", "Absolute pinned process adapter executable")
	flags.StringVar(&selected.snapshot, "snapshot", "", "Canonical public snapshot for a fresh process composition")
	flags.StringVar(&selected.workDir, "work-dir", "", "Controlled local process staging directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options{}, flag.ErrHelp
		}
		return options{}, fmt.Errorf("invalid consumer arguments")
	}
	if flags.NArg() != 0 || (selected.adapter == "") != (selected.snapshot == "") || (selected.adapter == "" && selected.workDir != "") {
		return options{}, fmt.Errorf("select both adapter and snapshot for process inspection")
	}
	if selected.adapter != "" && !filepath.IsAbs(selected.adapter) {
		return options{}, fmt.Errorf("adapter executable must use an absolute path")
	}
	return selected, nil
}

func run(args []string, output io.Writer) error {
	selected, err := parseOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		if _, err := io.WriteString(output, "Usage: sdk-consumer [--adapter ABS --snapshot PATH [--work-dir PATH]]\n"); err != nil {
			return fmt.Errorf("write consumer usage failed")
		}
		return nil
	}
	if err != nil {
		return err
	}
	report, err := proveSDK()
	if err != nil {
		return err
	}
	if selected.adapter != "" {
		process, err := inspectProcess(selected)
		if err != nil {
			return err
		}
		report.Process = &process
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return fmt.Errorf("write scoped consumer report failed")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
