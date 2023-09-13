package types

import (
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
)

type RegisteredRule struct {
	Number    int
	Rule      scan.Rule
	CheckFunc scan.CheckFunc
}

func (r *RegisteredRule) HasLogic() bool {
	return r.CheckFunc != nil
}

func (r *RegisteredRule) Evaluate(s *state.State) scan.Results {
	if r.CheckFunc == nil {
		return nil
	}
	results := r.CheckFunc(s)
	for i := range results {
		results[i].SetRule(r.Rule)
	}
	return results
}

func (r *RegisteredRule) GetRule() scan.Rule {
	return r.Rule
}

func (r *RegisteredRule) AddLink(link string) {
	r.Rule.Links = append([]string{link}, r.Rule.Links...)
}
