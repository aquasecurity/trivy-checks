package custom.regal.rules.naming["deny-rule_test"]

import rego.v1

import data.custom.regal.rules.naming["deny-rule"] as rule

test_rule_named_startswith_not_allowed if {
	module := regal.parse_module("example.rego", `
	package policy

	deny_foo := true`)

	r := rule.report with input as module

	r == {{
		"category": "naming",
		"description": "Ensures that no rules in the check are named with the prefix 'deny_'",
		"related_resources": [{
			"description": "documentation",
			"ref": "https://github.com/aquasecurity/trivy-checks/pull/283",
		}],
		"level": "error",
		"location": {
			"file": "example.rego",
			"row": 4,
			"col": 2,
			"end": {
				"row": 4,
				"col": 18,
			},
			"text": "\tdeny_foo := true",
		},
		"title": "deny-rule",
	}}
}
