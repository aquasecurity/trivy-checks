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
	if r.Examples != "" {
		return r.Examples
	}

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

type ProviderExamples struct {
	Good blocks `yaml:"good,omitempty"`
	Bad  blocks `yaml:"bad,omitempty"`
}

func (e ProviderExamples) IsEmpty() bool {
	return len(e.Good) == 0 && len(e.Bad) == 0
}

type CheckExamples map[string]ProviderExamples

func (e CheckExamples) Format() {
	for providerName, examples := range e {
		if formatFunc, ok := formatters[providerName]; ok {
			examples.Good.format(formatFunc)
			examples.Bad.format(formatFunc)
		}
		e[providerName] = examples
	}
}

type blockString string

func (b blockString) MarshalYAML() (interface{}, error) {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.LiteralStyle,
		Value: strings.TrimSuffix(string(b), "\n"),
	}, nil
}

type blocks []blockString

func (b blocks) ToStrings() []string {
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

var formatters = map[string]func(blockString) blockString{
	"terraform":      formatHCL,
	"cloudformation": formatCFT,
	"kubernetes":     formatYAML,
}

func formatHCL(b blockString) blockString {
	return blockString(hclwrite.Format([]byte(strings.Trim(string(b), " \n"))))
}

func formatCFT(b blockString) blockString {
	tmpl, err := parse.String(string(b))
	if err != nil {
		panic(err)
	}

	return blockString(format.CftToYaml(tmpl))
}

func formatYAML(b blockString) blockString {
	var v any
	if err := yaml.Unmarshal([]byte(b), &v); err != nil {
		panic(err)
	}
	ret, err := yaml.Marshal(v)
	if err != nil {
		panic(err)
	}
	return blockString(ret)
}
