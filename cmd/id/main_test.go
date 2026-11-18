package main

import (
	"io/fs"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	trivy_checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

var idPattern = regexp.MustCompile(`^([A-Z][A-Z0-9]*)-(\d{4})$`)

type definition struct {
	path string
	id   string
}

func TestIDsNotAboveLast(t *testing.T) {
	defs := append(checkDefinitions(t), commandDefinitions(t)...)
	for _, def := range defs {
		m := idPattern.FindStringSubmatch(def.id)
		if m == nil {
			t.Errorf("%s: ID %q does not match the PREFIX-NNNN format", def.path, def.id)
			continue
		}

		prefix := m[1]
		n, err := strconv.Atoi(m[2])
		require.NoError(t, err)

		last, ok := lastIDs[prefix]
		if !ok {
			t.Errorf("%s: prefix of %s is missing in lastIDs", def.path, def.id)
			continue
		}
		if n > last {
			t.Errorf("%s: %s is above the last taken ID %s-%04d, raise it in lastIDs", def.path, def.id, prefix, last)
		}
	}
}

func TestIDsUnique(t *testing.T) {
	seen := make(map[string]string)
	for _, def := range append(checkDefinitions(t), commandDefinitions(t)...) {
		if other, ok := seen[def.id]; ok {
			t.Errorf("%s: %s is already used in %s", def.path, def.id, other)
			continue
		}
		seen[def.id] = def.path
	}
}

func checkDefinitions(t *testing.T) []definition {
	t.Helper()

	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	require.NoError(t, err)

	defs := make([]definition, 0, len(checksMetadata))
	for path, meta := range checksMetadata {
		defs = append(defs, definition{path: path, id: meta.ID()})
	}
	return defs
}

func commandDefinitions(t *testing.T) []definition {
	t.Helper()

	var defs []definition
	err := fs.WalkDir(trivy_checks.EmbeddedK8sCommandsFileSystem, "commands/kubernetes", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		b, err := fs.ReadFile(trivy_checks.EmbeddedK8sCommandsFileSystem, path)
		if err != nil {
			return err
		}

		var commands []struct {
			ID string `yaml:"id"`
		}
		if err := yaml.Unmarshal(b, &commands); err != nil {
			return err
		}

		for _, c := range commands {
			defs = append(defs, definition{path: path, id: c.ID})
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, defs)
	return defs
}
