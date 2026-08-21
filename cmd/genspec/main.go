package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const complianceDirPath = "pkg/compliance/"

var specs = map[framework.Framework]*iacTypes.Spec{
	framework.CIS_AWS_1_2: {
		ID:          "aws-cis-1.2",
		Title:       "AWS CIS Foundations v1.2",
		Description: "AWS CIS Foundations",
		Version:     "1.2",
		Platform:    "aws",
		Type:        "cis",
		RelatedResources: []string{
			"https://www.cisecurity.org/benchmark/amazon_web_services",
		},
	},
	framework.CIS_AWS_1_4: {
		ID:          "aws-cis-1.4",
		Title:       "AWS CIS Foundations v1.4",
		Description: "AWS CIS Foundations",
		Version:     "1.4",
		Platform:    "aws",
		Type:        "cis",
		RelatedResources: []string{
			"https://www.cisecurity.org/benchmark/amazon_web_services",
		},
	},
}

func main() {
	frameworks := make([]framework.Framework, 0, len(specs))
	for f := range specs {
		frameworks = append(frameworks, f)
	}

	for _, meta := range lo.Must(metadata.LoadDefaultChecksMetadata()) {
		for f, controlIDs := range meta.Frameworks() {
			if f == "default" {
				continue
			}

			ff := framework.Framework(f)
			spec, exists := specs[ff]
			if !exists {
				log.Printf("Unknown framework: %s", f)
				continue
			}

			for _, id := range controlIDs {
				spec.Controls = append(spec.Controls, iacTypes.Control{
					ID:          id,
					Name:        lo.LastOrEmpty(meta.Aliases()),
					Description: meta.Title,
					Severity:    iacTypes.Severity(meta.Severity()),
					Checks:      []iacTypes.SpecCheck{{ID: meta.ID()}},
				})
			}
		}
	}

	for _, spec := range specs {
		sort.Slice(spec.Controls, func(i, j int) bool {
			return strings.Compare(spec.Controls[i].ID, spec.Controls[j].ID) < 0
		})
	}

	for _, c := range specs {
		lo.Must0(writeCompliance(c, complianceDirPath))
	}
}

func writeCompliance(spec *iacTypes.Spec, path string) error {
	file, err := os.Create(filepath.Join(path, fmt.Sprintf("%s.yaml", spec.ID)))
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	return encoder.Encode(iacTypes.ComplianceSpec{Spec: *spec})
}
