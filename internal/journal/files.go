// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func directory(path string, create bool) (string, *os.Root, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && create {
			err = os.Mkdir(current, 0o700)
			if err != nil && !os.IsExist(err) {
				return "", nil, fmt.Errorf("create journal directory: %w", err)
			}
			if err == nil {
				if err := syncCreatedDirectory(current); err != nil {
					return "", nil, err
				}
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return "", nil, fmt.Errorf("inspect journal directory: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", nil, fmt.Errorf("journal directory must not contain symlinks")
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", nil, err
	}
	if err := owned(info, true); err != nil {
		return "", nil, err
	}
	root, err := os.OpenRoot(abs)
	return abs, root, err
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
		return fmt.Errorf("journal storage must be owned by the current user")
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) {
		return fmt.Errorf("journal storage must contain regular files and directories")
	}
	want := os.FileMode(0o600)
	if dir {
		want = 0o700
	}
	if info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (!dir && stat.Nlink != 1) {
		return fmt.Errorf("journal storage requires private permissions and no hard links (mode %o, links %d)", info.Mode().Perm(), stat.Nlink)
	}
	return nil
}

func regular(root *os.Root, name string, flags int, create bool) (*os.File, error) {
	if info, err := root.Lstat(name); err == nil {
		if err := owned(info, false); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) || !create {
		return nil, err
	}
	if create {
		flags |= os.O_CREATE
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

func syncDirectory(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
