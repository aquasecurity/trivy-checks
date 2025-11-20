package bundler

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
)

type copyJob struct {
	from string
	to   string
}

// FileFilter is a function that determines whether a given file path
// should be included (returns true) or excluded (returns false) from the bundle.
type FileFilter func(path string) bool

// Bundler is responsible for preparing and archiving a bundle of files from a root directory
type Bundler struct {
	root    string
	fsys    fs.FS
	prefix  string // Prefix path inside the archive, e.g. "bundle"
	filters []FileFilter

	jobs  []copyJob
	files map[string]string // map of source file paths to their relative destination paths in the bundle
}

type Option func(*Bundler)

// WithFilters adds additional FileFilters to control which files are included.
func WithFilters(filters ...FileFilter) Option {
	return func(b *Bundler) {
		b.filters = append(b.filters, filters...)
	}
}

// New creates a new Bundler instance rooted at at the given directory and using the provided fs.FS.
func New(root string, fsys fs.FS, opts ...Option) *Bundler {
	b := &Bundler{
		root:    root,
		fsys:    fsys,
		prefix:  "",
		filters: defaultFilters(),
		jobs: []copyJob{
			{"checks/kubernetes", "policies/kubernetes/policies"},
			{"checks/cloud", "policies/cloud/policies"},
			{"checks/docker", "policies/docker/policies"},

			{"lib/kubernetes", "policies/kubernetes/lib"},
			{"lib/cloud", "policies/cloud/lib"},
			{"lib/docker", "policies/docker/lib"},
			{"lib/test", "policies/test/lib"},

			{"commands/kubernetes", "commands/kubernetes"},
			{"commands/config", "commands/config"},

			{"pkg/compliance", "specs/compliance"},
		},
	}

	for _, opt := range opts {
		opt(b)
	}
	return b
}

func defaultFilters() []FileFilter {
	return []FileFilter{
		func(path string) bool {
			// Excluding YAML only for the checks directory
			if !strings.HasPrefix(path, "checks") {
				return true
			}
			ext := filepath.Ext(path)
			return ext == ".rego"
		},
		func(path string) bool {
			ext := filepath.Ext(path)
			return ext != ".go" && ext != ".md"
		},
		func(path string) bool {
			return !strings.HasSuffix(path, "_test.rego")
		},
	}
}

// Build prepares the list of files to archive and writes
// the resulting archive as a compressed tar.gz to the provided io.Writer.
func (b *Bundler) Build(w io.Writer) error {
	if err := b.prepareFiles(); err != nil {
		return err
	}

	return b.archive(w)
}

// prepareFiles scans the root directory, applies filters, and prepares the list of files to be archived
func (b *Bundler) prepareFiles() error {
	b.files = make(map[string]string)
	for _, job := range b.jobs {
		rootPath := filepath.Join(b.root, job.from)
		var jobCount int
		walkFn := func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(b.root, path)
			if err != nil {
				return err
			}

			for _, f := range b.filters {
				if !f(rel) {
					return nil
				}
			}

			relToJobFrom, err := filepath.Rel(rootPath, path)
			if err != nil {
				return err
			}
			b.files[path] = filepath.ToSlash(filepath.Join(job.to, relToJobFrom))
			jobCount++
			return nil
		}

		if err := fs.WalkDir(b.fsys, rootPath, walkFn); err != nil {
			return err
		}

		log.Printf("Prepared %d files from %q to %q", jobCount, rootPath, job.to)
	}

	return nil
}

// archive writes all prepared files into a compressed tar.gz archive
func (b *Bundler) archive(w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	var added int
	for src, dst := range b.files {
		err := b.addFileToTar(tw, src, b.prefix+dst)
		if err != nil {
			return fmt.Errorf("add file to tar: %w", err)
		}
		added++
	}

	log.Printf("Added %d files to archive", added)
	return nil
}

func (b *Bundler) addFileToTar(tw *tar.Writer, src, dst string) error {
	fi, err := fs.Stat(b.fsys, src)
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	header.Name = dst

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	f, err := b.fsys.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tw, f)
	return err
}
