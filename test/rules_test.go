package test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/simar7/trivy-misconf-rules/internal/rules"
)

func TestAVDIDs(t *testing.T) {
	existing := make(map[string]struct{})
	for _, rule := range rules.GetFrameworkRules(framework.ALL) {
		t.Run(rule.Rule().LongID(), func(t *testing.T) {
			if rule.Rule().AVDID == "" {
				t.Errorf("Rule has no AVD ID: %#v", rule)
				return
			}
			if _, ok := existing[rule.Rule().AVDID]; ok {
				t.Errorf("Rule detected with duplicate AVD ID: %s", rule.Rule().AVDID)
			}
		})
		existing[rule.Rule().AVDID] = struct{}{}
	}
}

func TestRulesAgainstExampleCode(t *testing.T) {
	for _, rule := range rules.GetFrameworkRules(framework.ALL) {
		testName := fmt.Sprintf("%s/%s", rule.Rule().AVDID, rule.Rule().LongID())
		t.Run(testName, func(t *testing.T) {
			rule := rule
			t.Parallel()

			t.Run("avd docs", func(t *testing.T) {
				provider := strings.ToLower(rule.Rule().Provider.ConstName())
				service := strings.ToLower(strings.ReplaceAll(rule.Rule().Service, "-", ""))
				_, err := os.Stat(filepath.Join("..", "avd_docs", provider, service, rule.Rule().AVDID, "docs.md"))
				require.NoError(t, err)
			})
		})
	}
}
