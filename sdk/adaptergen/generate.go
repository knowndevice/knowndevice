// SPDX-License-Identifier: Apache-2.0

package adaptergen

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/template"
)

var (
	ErrOptions     = errors.New("adapter generation options refused")
	ErrDestination = errors.New("adapter generation destination refused; existing and partial directories are never overwritten")
	ErrGeneration  = errors.New("adapter generation failed; preserve any partial destination and select a new directory")
	ErrManifest    = errors.New("adapter manifest binding refused")
)

// Options requires an existing symlink-free root and a new single directory name.
// SDKReplace is an explicit local SDK module selection, not a publication claim.
type Options struct {
	Root       string
	Directory  string
	Name       string
	Module     string
	SDKReplace string
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
}

type Result struct {
	Directory string `json:"directory"`
	Files     []File `json:"files"`
}

type outputFile struct {
	path string
	data []byte
	mode os.FileMode
}

//go:embed templates/*
var sourceTemplates embed.FS

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
var modulePart = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$`)

func portableComponent(value string) bool {
	base := strings.SplitN(value, ".", 2)[0]
	switch base {
	case "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9":
		return false
	}
	return true
}

func validName(value string) bool {
	return len(value) <= 63 && namePattern.MatchString(value) && portableComponent(value)
}

func validModule(value string) bool {
	if len(value) > 255 || strings.Contains(value, "\\") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 || !strings.Contains(parts[0], ".") || parts[0] == "gopkg.in" {
		return false
	}
	for _, part := range parts {
		if len(part) > 63 || !modulePart.MatchString(part) || strings.Contains(part, "..") || strings.HasSuffix(part, ".git") || strings.HasSuffix(part, ".") || !portableComponent(part) {
			return false
		}
	}
	for _, label := range strings.Split(parts[0], ".") {
		if label == "" || strings.ContainsAny(label, "_ ") || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	last := parts[len(parts)-1]
	if len(last) > 1 && last[0] == 'v' && last[1] >= '0' && last[1] <= '9' {
		version, err := strconv.Atoi(last[1:])
		if err != nil || version < 2 || last[1] == '0' {
			return false
		}
	}
	return true
}

func absolutePath(value string) bool {
	return value != "" && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsAny(value, "\\\x00\r\n")
}

// openDirectory checks every component, then verifies the opened rooted handle.
// Rooted access prevents an escaped write if a component is concurrently replaced.
func openDirectory(value string) (*os.Root, error) {
	if !absolutePath(value) {
		return nil, ErrOptions
	}
	anchor, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, ErrOptions
	}
	relative := strings.TrimPrefix(value, string(filepath.Separator))
	if relative == "" {
		return anchor, nil
	}
	current := anchor
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		info, statErr := current.Lstat(component)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, ErrOptions
		}
		next, openErr := current.OpenRoot(component)
		if openErr != nil {
			current.Close()
			return nil, ErrOptions
		}
		opened, openedErr := next.Stat(".")
		after, afterErr := current.Lstat(component)
		current.Close()
		if openedErr != nil || afterErr != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) || !os.SameFile(info, after) {
			next.Close()
			return nil, ErrOptions
		}
		current = next
	}
	return current, nil
}

func validateOptions(options Options) error {
	if !validName(options.Name) || !validName(options.Directory) || !validModule(options.Module) || options.Module == "github.com/knowndevice/knowndevice" || !absolutePath(options.Root) || !absolutePath(options.SDKReplace) {
		return ErrOptions
	}
	root, err := openDirectory(options.SDKReplace)
	if err != nil {
		return ErrOptions
	}
	defer root.Close()
	info, err := root.Lstat("go.mod")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return ErrOptions
	}
	file, err := root.OpenFile("go.mod", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrOptions
	}
	defer file.Close()
	opened, err := file.Stat()
	after, afterErr := root.Lstat("go.mod")
	if err != nil || afterErr != nil || !opened.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) || !os.SameFile(info, after) {
		return ErrOptions
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 || !bytes.HasPrefix(data, []byte("module github.com/knowndevice/knowndevice\n")) {
		return ErrOptions
	}
	return nil
}

func render(options Options) ([]outputFile, error) {
	templateManifest, err := Describe(options.Name)
	if err != nil {
		return nil, err
	}
	manifest, err := json.MarshalIndent(templateManifest, "", "  ")
	if err != nil {
		return nil, ErrGeneration
	}
	files := []outputFile{{"adapter-template.json", append(manifest, '\n'), 0600}, {"adapter.schema.json", append([]byte(nil), ManifestSchema...), 0600}}
	sources := map[string]string{
		"go.mod": "go.mod.tmpl", "go.sum": "go.sum.tmpl", ".gitignore": "gitignore.tmpl", "README.md": "README.md.tmpl",
		"adapter.go": "adapter.go.tmpl", "conformance_test.go": "conformance_test.go.tmpl", "fixtures/expectations.json": "expectations.json.tmpl",
		"cmd/adapter/main.go": "adapter-main.go.tmpl", "cmd/conformance/main.go": "conformance-main.go.tmpl", "cmd/manifest/main.go": "manifest-main.go.tmpl", "scripts/ci.sh": "ci.sh.tmpl",
	}
	for name, source := range sources {
		data, err := sourceTemplates.ReadFile("templates/" + source)
		if err != nil {
			return nil, ErrGeneration
		}
		parsed, err := template.New(name).Funcs(template.FuncMap{"quote": strconv.Quote}).Parse(string(data))
		if err != nil {
			return nil, ErrGeneration
		}
		var output bytes.Buffer
		if err := parsed.Execute(&output, options); err != nil {
			return nil, ErrGeneration
		}
		content := output.Bytes()
		if strings.HasSuffix(name, ".go") {
			content, err = format.Source(content)
			if err != nil {
				return nil, ErrGeneration
			}
		}
		mode := os.FileMode(0600)
		if name == "scripts/ci.sh" {
			mode = 0700
		}
		files = append(files, outputFile{name, content, mode})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

// Generate creates one new private directory, with exclusive writes for every file.
// It never removes a partial result: retain it as evidence and choose a new destination.
func Generate(options Options) (Result, error) {
	if err := validateOptions(options); err != nil {
		return Result{}, err
	}
	files, err := render(options)
	if err != nil {
		return Result{}, err
	}
	root, err := openDirectory(options.Root)
	if err != nil {
		return Result{}, ErrDestination
	}
	defer root.Close()
	if err := root.Mkdir(options.Directory, 0700); err != nil {
		return Result{}, ErrDestination
	}
	info, err := root.Lstat(options.Directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Result{}, ErrGeneration
	}
	destination, err := root.OpenRoot(options.Directory)
	if err != nil {
		return Result{}, ErrGeneration
	}
	defer destination.Close()
	opened, err := destination.Stat(".")
	after, afterErr := root.Lstat(options.Directory)
	if err != nil || afterErr != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) || !os.SameFile(info, after) {
		return Result{}, ErrGeneration
	}
	directories := map[string]*os.Root{".": destination}
	defer func() {
		for name, directory := range directories {
			if name != "." {
				directory.Close()
			}
		}
	}()
	var ensureDirectory func(string) (*os.Root, error)
	ensureDirectory = func(name string) (*os.Root, error) {
		if directory := directories[name]; directory != nil {
			return directory, nil
		}
		parent, err := ensureDirectory(filepath.Dir(name))
		if err != nil || parent.Mkdir(filepath.Base(name), 0700) != nil {
			return nil, ErrGeneration
		}
		info, err := parent.Lstat(filepath.Base(name))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrGeneration
		}
		directory, err := parent.OpenRoot(filepath.Base(name))
		if err != nil {
			return nil, ErrGeneration
		}
		opened, openedErr := directory.Stat(".")
		after, afterErr := parent.Lstat(filepath.Base(name))
		if openedErr != nil || afterErr != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) || !os.SameFile(info, after) {
			directory.Close()
			return nil, ErrGeneration
		}
		directories[name] = directory
		return directory, nil
	}
	result := Result{Directory: options.Directory, Files: []File{}}
	for _, selected := range files {
		directory, err := ensureDirectory(filepath.Dir(selected.path))
		if err != nil {
			return Result{}, ErrGeneration
		}
		file, err := directory.OpenFile(filepath.Base(selected.path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, selected.mode)
		if err != nil {
			return Result{}, ErrGeneration
		}
		_, writeErr := file.Write(selected.data)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return Result{}, ErrGeneration
		}
		digest := sha256.Sum256(selected.data)
		result.Files = append(result.Files, File{Path: selected.path, SHA256: hex.EncodeToString(digest[:]), Mode: selected.mode.String()})
	}
	return result, nil
}
