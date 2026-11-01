// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/knowndevice/knowndevice/sdk/adaptergen"
)

func TestUsageAndInvalidArguments(t *testing.T) {
	var output bytes.Buffer
	if run([]string{"--help"}, &output) != nil || output.String() != usage {
		t.Fatal("usage unavailable")
	}
	for _, args := range [][]string{{}, {"unexpected"}, {"--unknown", "secret-marker"}, {"--name"}} {
		output.Reset()
		err := run(args, &output)
		if !errors.Is(err, adaptergen.ErrOptions) || output.Len() != 0 || strings.Contains(err.Error(), "secret-marker") {
			t.Fatal("invalid arguments leaked input or succeeded")
		}
	}
}
