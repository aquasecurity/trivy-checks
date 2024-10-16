package examples

import (
	"strings"

	"github.com/aws-cloudformation/rain/cft/format"
	"github.com/aws-cloudformation/rain/cft/parse"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"gopkg.in/yaml.v3"

	trivy_checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func GetCheckExamples(r scan.Rule) (CheckExamples, string, error) {
	path := getCheckExamplesPath(r)
	if path == "" {
		return CheckExamples{}, "", nil
	}

	b, err := trivy_checks.EmbeddedPolicyFileSystem.ReadFile(path)
	if err != nil {
		return CheckExamples{}, "", err
	}

	var exmpls CheckExamples
	if err := yaml.Unmarshal(b, &exmpls); err != nil {
		return CheckExamples{}, "", err
	}

	return exmpls, path, nil
}

// TODO: use `examples` field after adding
func getCheckExamplesPath(r scan.Rule) string {
	for _, eng := range []*scan.EngineMetadata{r.Terraform, r.CloudFormation} {
		if eng == nil {
			continue
		}

		paths := append(eng.BadExamples, eng.GoodExamples...)
		for _, path := range paths {
			if path != "" {
				return path
			}
		}

	}

	return ""
}

type CheckExamples map[string]ProviderExamples

type blockString string

type blocks []blockString

func (b blocks) ToStrigns() []string {
	res := make([]string, 0, len(b))
	for _, bs := range b {
		res = append(res, string(bs))
	}
	return res
}

func (b blocks) format(fn func(blockString) blockString) {
	for i, block := range b {
		b[i] = fn(block)
	}
}

type ProviderExamples struct {
	Good blocks `yaml:"good,omitempty"`
	Bad  blocks `yaml:"bad,omitempty"`
}

func (e ProviderExamples) IsEmpty() bool {
	return len(e.Good) == 0 && len(e.Bad) == 0
}

func (b blockString) MarshalYAML() (interface{}, error) {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.LiteralStyle,
		Value: string(b),
	}, nil
}

func (e CheckExamples) Format() {
	for providerName, examples := range e {
		if formatFunc, ok := formatterMap[providerName]; ok {
			examples.Good.format(formatFunc)
			examples.Bad.format(formatFunc)
		}
		e[providerName] = examples
	}
}

var formatterMap = map[string]func(blockString) blockString{
	"terraform":      formatHCL,
	"cloudformation": formatCft,
}

func formatHCL(b blockString) blockString {
	return blockString(hclwrite.Format([]byte(strings.Trim(string(b), " \n"))))
}

func formatCft(b blockString) blockString {
	tmpl, err := parse.String(string(b))
	if err != nil {
		panic(err)
	}

	return blockString(format.CftToYaml(tmpl))
}
