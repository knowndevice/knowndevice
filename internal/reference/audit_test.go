// SPDX-License-Identifier: Apache-2.0

package reference

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditRegistryPathPreservesReservedCharacters(t *testing.T) {
	for _, suffix := range []string{"?audit", "#audit", "%audit"} {
		t.Run(suffix, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, "fresh"+suffix)
			if err = seed(dir); err != nil {
				t.Fatal(err)
			}
			s, err := openControl(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec("UPDATE metadata SET value=7 WHERE name='counter'"); err != nil {
				s.db.Close()
				s.lock.Close()
				t.Fatal(err)
			}
			s.db.Close()
			s.lock.Close()
			s, err = openControl(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.db.Close()
			defer s.lock.Close()
			counter, err := s.number(context.Background(), "counter")
			if err != nil || counter != 7 {
				t.Fatalf("registry counter did not survive reopen: %v, %d", err, counter)
			}
			entries, err := os.ReadDir(base)
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(dir) {
				t.Fatal("SQLite created a sibling outside the selected registry directory")
			}
		})
	}
}
