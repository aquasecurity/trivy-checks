package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const complianceDirPath = "pkg/specs/compliance/"

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

	// Clean up all Go checks
	rules.Reset()

	// Load Rego checks
	rego.LoadAndRegister()

	for _, rule := range rules.GetRegistered(frameworks...) {
		for f, controlIDs := range rule.Frameworks {
			for _, id := range controlIDs {
				specs[f].Controls = append(specs[f].Controls, iacTypes.Control{
					ID:          id,
					Name:        rule.ShortCode,
					Description: rule.Summary,
					Severity:    iacTypes.Severity(rule.Severity),
					Checks:      []iacTypes.SpecCheck{{ID: rule.AVDID}},
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
		if err := writeCompliance(c, complianceDirPath); err != nil {
			panic(err)
		}
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
