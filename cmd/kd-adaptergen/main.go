// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/knowndevice/knowndevice/sdk/adaptergen"
)

const usage = "Usage: kd-adaptergen --root ABS --dir NAME --name NAME --module DOMAIN/PATH --sdk-replace ABS\n"

func run(args []string, output io.Writer) error {
	var selected adaptergen.Options
	flags := flag.NewFlagSet("kd-adaptergen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&selected.Root, "root", "", "Existing absolute symlink-free output root")
	flags.StringVar(&selected.Directory, "dir", "", "New single directory name")
	flags.StringVar(&selected.Name, "name", "", "Adapter wrapper name")
	flags.StringVar(&selected.Module, "module", "", "Standalone Go module path")
	flags.StringVar(&selected.SDKReplace, "sdk-replace", "", "Explicit absolute local alpha SDK module directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(output, usage)
			return err
		}
		return adaptergen.ErrOptions
	}
	if flags.NArg() != 0 {
		return adaptergen.ErrOptions
	}
	result, err := adaptergen.Generate(selected)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return fmt.Errorf("adapter generation report write failed")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
