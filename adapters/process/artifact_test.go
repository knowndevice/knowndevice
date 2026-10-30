// SPDX-License-Identifier: Apache-2.0

package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactPinsAndConfinement(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("public artifact")
	if err := os.Mkdir(filepath.Join(root, "inside"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "inside", "artifact")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	a := Artifact{"inside/artifact", int64(len(data)), digestBytes(data)}
	if result, err := OpenArtifact(root, a); err != nil || string(result) != string(data) {
		t.Fatal("valid confined pin refused", err)
	}
	for _, path := range []string{"../artifact", "/artifact", "inside/../inside/artifact", "inside//artifact", "inside/./artifact", "inside\\artifact", "."} {
		bad := a
		bad.Path = path
		if _, err := OpenArtifact(root, bad); err == nil {
			t.Fatal("path escape accepted")
		}
	}
	for _, change := range []Artifact{{a.Path, a.Size + 1, a.SHA256}, {a.Path, a.Size, digestBytes([]byte("changed"))}, {a.Path, MaxExecutableBytes + 1, a.SHA256}, {"inside", 0, a.SHA256}} {
		if _, err := OpenArtifact(root, change); err == nil {
			t.Fatal("invalid artifact accepted")
		}
	}
	if err := os.Symlink(file, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenArtifact(root, Artifact{"link", a.Size, a.SHA256}); err == nil {
		t.Fatal("symlink accepted")
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(parent, "root-link")
	if err := os.Symlink(root, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenArtifact(linkRoot, a); err == nil {
		t.Fatal("symlink root accepted")
	}
	if _, err := OpenArtifact(filepath.Join(linkRoot, "inside"), Artifact{"artifact", a.Size, a.SHA256}); err == nil {
		t.Fatal("symlink root ancestor accepted")
	}
	if err := VerifyExecutable(file, a.SHA256); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecutable(filepath.Join(root, "link"), a.SHA256); err == nil {
		t.Fatal("symlink executable accepted")
	}
	if err := VerifyExecutable(file, digestBytes([]byte("changed"))); err == nil {
		t.Fatal("changed executable accepted")
	}
}
