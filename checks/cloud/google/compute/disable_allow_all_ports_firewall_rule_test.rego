package builtin.google.compute.google0072_test

import rego.v1

import data.builtin.google.compute.google0072 as check

test_deny_firewall_rule_allows_all_ports if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
			"ports": [{"start": {"value": 0}, "end": {"value": 65535}}],
		},
		"sourceranges": [{"value": "0.0.0.0/0"}],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_firewall_rule_allows_all_ports_implicitly if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
		},
		"sourceranges": [{"value": "0.0.0.0/0"}],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_firewall_rule_specific_ports if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
			"ports": [{"start": {"value": 80}, "end": {"value": 80}}],
		},
		"sourceranges": [{"value": "0.0.0.0/0"}],
	}]}}]}}}

	res := check.deny with input as inp
	res == set()
}
