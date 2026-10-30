// SPDX-License-Identifier: Apache-2.0

package process

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// Artifact is a host-side public artifact reference; it is never a wire URL/path.
type Artifact struct {
	Path   string
	Size   int64
	SHA256 string
}

// OpenArtifact reads one regular file through rooted access and verifies its exact bytes.
// Rooted access does not confine mounts or a subprocess's direct system calls.
func OpenArtifact(root string, a Artifact) ([]byte, error) {
	if a.Path == "" || a.Path == "." || len(a.Path) > 1024 || len(root) > 4096 || !filepath.IsAbs(root) || strings.Contains(a.Path, "\\") || path.IsAbs(a.Path) || path.Clean(a.Path) != a.Path || a.Size < 0 || a.Size > MaxExecutableBytes || !sha256ID.MatchString(a.SHA256) {
		return nil, ErrProtocol
	}
	if noSymlinks(root) != nil {
		return nil, ErrProtocol
	}
	for _, component := range strings.Split(a.Path, "/") {
		if component == "" || component == "." || component == ".." {
			return nil, ErrProtocol
		}
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, ErrProtocol
	}
	defer r.Close()
	components := strings.Split(a.Path, "/")
	for i := range components {
		info, err := r.Lstat(strings.Join(components[:i+1], "/"))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrProtocol
		}
		if i < len(components)-1 && !info.IsDir() {
			return nil, ErrProtocol
		}
	}
	// Nonblocking open also prevents a raced replacement by a FIFO from hanging.
	f, err := r.OpenFile(a.Path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrProtocol
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != a.Size {
		return nil, ErrProtocol
	}
	data, err := io.ReadAll(io.LimitReader(f, a.Size+1))
	if err != nil || int64(len(data)) != a.Size || digestBytes(data) != a.SHA256 {
		return nil, ErrProtocol
	}
	return data, nil
}

func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func executableBytes(file string) ([]byte, error) {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, ErrProtocol
	}
	if noSymlinks(file) != nil {
		return nil, ErrProtocol
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxExecutableBytes {
		return nil, ErrProtocol
	}
	r, err := os.OpenRoot(filepath.Dir(file))
	if err != nil {
		return nil, ErrProtocol
	}
	defer r.Close()
	f, err := r.OpenFile(filepath.Base(file), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrProtocol
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		return nil, ErrProtocol
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxExecutableBytes+1))
	if err != nil || int64(len(data)) != opened.Size() {
		return nil, ErrProtocol
	}
	return data, nil
}

func noSymlinks(file string) error {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return ErrProtocol
	}
	parent := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(file, string(filepath.Separator)), string(filepath.Separator)) {
		parent = filepath.Join(parent, component)
		info, err := os.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrProtocol
		}
	}
	return nil
}

// ExecutableDigest identifies bounded regular executable bytes without starting them.
func ExecutableDigest(file string) (string, error) {
	data, err := executableBytes(file)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

// VerifyExecutable checks the pinned artifact before a caller stages or writes state.
func VerifyExecutable(file, expectedDigest string) error {
	if !sha256ID.MatchString(expectedDigest) {
		return ErrProtocol
	}
	digest, err := ExecutableDigest(file)
	if err != nil || digest != expectedDigest {
		return ErrProtocol
	}
	return nil
}
