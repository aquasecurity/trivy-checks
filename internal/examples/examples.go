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
	if r.Examples == "" {
		return CheckExamples{}, "", nil
	}

	b, err := trivy_checks.EmbeddedPolicyFileSystem.ReadFile(r.Examples)
	if err != nil {
		return CheckExamples{}, "", err
	}

	var exmpls CheckExamples
	if err := yaml.Unmarshal(b, &exmpls); err != nil {
		return CheckExamples{}, "", err
	}

	return exmpls, r.Examples, nil
}

type ProviderExamples struct {
	Links []string `yaml:"links,omitempty"`
	Good  CodeBlocks   `yaml:"good,omitempty"`
	Bad   CodeBlocks   `yaml:"bad,omitempty"`
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

type CodeBlocks []CodeBlock

func (b CodeBlocks) ToStrings() []string {
	res := make([]string, 0, len(b))
	for _, bs := range b {
		res = append(res, string(bs))
	}
	return res
}

func (b CodeBlocks) format(fn func(CodeBlock) CodeBlock) {
	for i, block := range b {
		b[i] = fn(block)
	}
}

type CodeBlock string

func (b CodeBlock) MarshalYAML() (any, error) {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.LiteralStyle,
		Value: strings.TrimSuffix(string(b), "\n"),
	}, nil
}

var formatters = map[string]func(CodeBlock) CodeBlock{
	"terraform":      formatHCL,
	"cloudformation": formatCFT,
	"kubernetes":     formatYAML,
}

func formatHCL(b CodeBlock) CodeBlock {
	return CodeBlock(hclwrite.Format([]byte(strings.Trim(string(b), " \n"))))
}

func formatCFT(b CodeBlock) CodeBlock {
	tmpl, err := parse.String(string(b))
	if err != nil {
		panic(err)
	}

	return CodeBlock(format.CftToYaml(tmpl))
}

func formatYAML(b CodeBlock) CodeBlock {
	var v any
	if err := yaml.Unmarshal([]byte(b), &v); err != nil {
		panic(err)
	}
	ret, err := yaml.Marshal(v)
	if err != nil {
		panic(err)
	}
	return CodeBlock(ret)
}
