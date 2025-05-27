package metadata

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/samber/lo"

	trivy_checks "github.com/aquasecurity/trivy-checks"
)

func LoadDefaultChecksMetadata() (map[string]Metadata, error) {
	return LoadChecksMetadata(trivy_checks.EmbeddedPolicyFileSystem)
}

func LoadChecksMetadata(fsys fs.FS) (map[string]Metadata, error) {
	res, err := loader.NewFileLoader().
		WithFS(fsys).
		WithProcessAnnotation(true).
		Filtered([]string{"."}, func(abspath string, info fs.FileInfo, depth int) bool {
			return isNotRegoFile(info)
		})

	if err != nil {
		return nil, fmt.Errorf("load Rego: %w", err)
	}

	checksMetadata := make(map[string]Metadata)
	for path, module := range res.ParsedModules() {
		annotations := packageAnnotations(module)
		if len(annotations) != 1 {
			// TODO: so the check has an deprecated way of specifying metadata
			continue
		}

		checksMetadata[path] = annotations[0].Custom
		checksMetadata[path]["description"] = annotations[0].Description
		checksMetadata[path]["links"] = relatedResourcesToLinks(annotations[0].RelatedResources)
	}
	return checksMetadata, nil
}

func relatedResourcesToLinks(relatedResources []*ast.RelatedResourceAnnotation) []string {
	var links []string
	for _, resource := range relatedResources {
		links = append(links, resource.Ref.String())
	}
	return links
}

func isNotRegoFile(fi fs.FileInfo) bool {
	return !fi.IsDir() && (!isRegoFile(fi.Name()) || isDotFile(fi.Name()))
}

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, "_test.rego")
}

func isDotFile(name string) bool {
	return strings.HasPrefix(name, ".")
}

func packageAnnotations(module *ast.Module) []*ast.Annotations {
	return lo.Filter(module.Annotations, func(annot *ast.Annotations, _ int) bool {
		return annot.Scope == "package"
	})
}
