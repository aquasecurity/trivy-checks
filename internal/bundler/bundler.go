package bundler

import (
	"archive/tar"
	"bytes"
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

// PlainTransform modifies the raw bytes of a file before it is added to the bundle.
type PlainTransform func(path string, raw []byte) []byte

// Bundler is responsible for preparing and archiving a bundle of files from a root directory
type Bundler struct {
	root            string
	fsys            fs.FS
	prefix          string // Prefix path inside the archive, e.g. "bundle"
	githubRef       string // GitHub ref string, e.g. "refs/tags/v1.2.3"
	filters         []FileFilter
	plainTransforms []PlainTransform

	jobs     []copyJob
	files    map[string]string // map of source file paths to their relative destination paths in the bundle
	manifest []byte            // prepared manifest content with placeholders replaced
}

type Option func(*Bundler)

// WithFilters adds additional FileFilters to control which files are included.
func WithFilters(filters ...FileFilter) Option {
	return func(b *Bundler) {
		b.filters = append(b.filters, filters...)
	}
}

// WithPlainTransforms adds one or more PlainTransform functions to the Bundler.
// Transforms are applied in order to files before bundling.
func WithPlainTransforms(transforms ...PlainTransform) Option {
	return func(b *Bundler) {
		b.plainTransforms = append(b.plainTransforms, transforms...)
	}
}

// WithGithubRef sets the GitHub ref string to be used for manifest substitution.
// The ref should be in the format "refs/tags/v1.2.3".
func WithGithubRef(ref string) Option {
	return func(b *Bundler) {
		b.githubRef = ref
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

// Build prepares the list of files to archive, processes the manifest, and writes
// the resulting archive as a compressed tar.gz to the provided io.Writer.
func (b *Bundler) Build(w io.Writer) error {
	if err := b.prepareFiles(); err != nil {
		return err
	}
	if err := b.prepareManifest(); err != nil {
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

// prepareManifest reads the manifest template file, replaces the placeholder
// "[GITHUB_SHA]" with the GitHub release version extracted from b.githubRef
func (b *Bundler) prepareManifest() error {
	const (
		placeholder = "[GITHUB_SHA]"
		prefix      = "refs/tags/v"
	)

	data, err := fs.ReadFile(b.fsys, filepath.Join(b.root, "checks", ".manifest"))
	if err != nil {
		return fmt.Errorf("read .manifest: %w", err)
	}

	if b.githubRef != "" {
		releaseVersion, ok := strings.CutPrefix(b.githubRef, prefix)
		if !ok {
			log.Printf("GitHub ref %q does not start with %q — using unchanged value", b.githubRef, prefix)
		}
		log.Printf("Using GitHub ref %q -> release version %q", b.githubRef, releaseVersion)
		data = bytes.ReplaceAll(data, []byte(placeholder), []byte(releaseVersion))
	}

	b.manifest = data
	return nil
}

// archive writes all prepared files and the manifest into a compressed tar.gz archive
func (b *Bundler) archive(w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	if err := b.writeManifest(tw); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

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

func (b *Bundler) writeManifest(tw *tar.Writer) error {
	hdr := &tar.Header{
		Name: b.prefix + ".manifest",
		Mode: 0o644,
		Size: int64(len(b.manifest)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write manifest header: %w", err)
	}
	if _, err := tw.Write(b.manifest); err != nil {
		return fmt.Errorf("write manifest content: %w", err)
	}
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

	data, err := fs.ReadFile(b.fsys, src)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	for _, transform := range b.plainTransforms {
		data = transform(src, data)
	}

	header.Name = dst
	header.Size = int64(len(data))
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}

	return nil
}
