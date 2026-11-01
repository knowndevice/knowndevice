// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/knowndevice/knowndevice/internal/device"
)

func decodeJSON(data []byte, value any) error {
	if err := device.CheckVersionFields(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("key-store metadata contains trailing data")
	}
	return nil
}

func openDirectory(path string, create bool) (*os.Root, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && create {
			err = os.Mkdir(current, 0o700)
			if err != nil && !os.IsExist(err) {
				return nil, fmt.Errorf("create key-store directory: %w", err)
			}
			if err == nil {
				if err := syncCreatedDirectory(current); err != nil {
					return nil, err
				}
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("key-store path must not contain symlinks")
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if err := owned(info, true); err != nil {
		return nil, err
	}
	return os.OpenRoot(abs)
}

func syncCreatedDirectory(path string) error {
	for _, directory := range []string{path, filepath.Dir(path)} {
		f, err := os.Open(directory)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func owned(info os.FileInfo, dir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("key storage must be owned by the current user")
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) {
		return fmt.Errorf("key storage requires regular files and directories")
	}
	want := os.FileMode(0o600)
	if dir {
		want = 0o700
	}
	if info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (!dir && stat.Nlink != 1) {
		return fmt.Errorf("key storage requires private permissions and no hard links (mode %o, links %d)", info.Mode().Perm(), stat.Nlink)
	}
	return nil
}

func openFile(root *os.Root, name string, flags int) (*os.File, error) {
	if info, err := root.Lstat(name); err == nil {
		if err := owned(info, false); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) || flags&os.O_CREATE == 0 {
		return nil, err
	}
	f, err := root.OpenFile(name, flags|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		err = owned(info, false)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func readFile(root *os.Root, name string) ([]byte, error) {
	return readFileLimit(root, name, 256<<10)
}

func readFileLimit(root *os.Root, name string, limit int) ([]byte, error) {
	f, err := openFile(root, name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("key-store artifact exceeds limit")
	}
	return data, nil
}

func writeFile(root *os.Root, name string, data []byte) error {
	f, err := openFile(root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	return errorsWithClose(err, f.Close())
}

func syncFile(root *os.Root, name string) error {
	f, err := openFile(root, name, os.O_RDONLY)
	if err != nil {
		return err
	}
	return errorsWithClose(f.Sync(), f.Close())
}

func errorsWithClose(err, closeErr error) error {
	if err != nil {
		return err
	}
	return closeErr
}

func syncDir(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func subdirectory(root *os.Root, name string) (*os.Root, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := owned(info, true); err != nil {
		return nil, err
	}
	return root.OpenRoot(name)
}

func entries(root *os.Root) ([]os.DirEntry, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}
