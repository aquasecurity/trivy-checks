package builtin.google.compute.google0027_test

import rego.v1

import data.builtin.google.compute.google0027 as check
import data.lib.test

test_deny_ingress_rule_with_multiple_public_sources if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
		},
		"sourceranges": [
			{"value": "0.0.0.0/0"},
			{"value": "1.2.3.4/32"},
		],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ingress_rule_with_public_source_address if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
		},
		"sourceranges": [{"value": "1.2.3.4/32"}],
	}]}}]}}}

	res := check.deny with input as inp
	res == set()
}
