// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"knowndevice.local/knowndevice/internal/reference"
	"os"
)

func main() {
	if err := reference.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
