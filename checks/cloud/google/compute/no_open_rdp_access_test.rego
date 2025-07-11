package builtin.google.compute.google0070_test

import rego.v1

import data.builtin.google.compute.google0070 as check

test_deny_access_with_multiple_public_sources if {
	inp := {"google": {"compute": {"networks": [{"firewall": {
		"sourcetags": [],
		"targettags": [],
		"ingressrules": [{
			"firewallrule": {
				"isallow": {"value": true},
				"enforced": {"value": true},
				"protocol": {"value": "tcp"},
				"ports": [{"start": {"value": 3389}, "end": {"value": 3389}}],
			},
			"sourceranges": [
				{"value": "0.0.0.0/0"},
				{"value": "1.2.3.4/32"},
			],
		}],
	}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_access_with_restricted_source_address if {
	inp := {"google": {"compute": {"networks": [{"firewall": {
		"sourcetags": [],
		"targettags": [],
		"ingressrules": [{
			"firewallrule": {
				"isallow": {"value": true},
				"enforced": {"value": true},
				"protocol": {"value": "tcp"},
				"ports": [{"start": {"value": 3389}, "end": {"value": 3389}}],
			},
			"sourceranges": [{"value": "1.2.3.4/32"}],
		}],
	}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_access_with_different_port if {
	inp := {"google": {"compute": {"networks": [{"firewall": {
		"sourcetags": [],
		"targettags": [],
		"ingressrules": [{
			"firewallrule": {
				"isallow": {"value": true},
				"enforced": {"value": true},
				"protocol": {"value": "tcp"},
				"ports": [{"start": {"value": 80}, "end": {"value": 80}}],
			},
			"sourceranges": [{"value": "0.0.0.0/0"}],
		}],
	}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_access_with_different_protocol if {
	inp := {"google": {"compute": {"networks": [{"firewall": {
		"sourcetags": [],
		"targettags": [],
		"ingressrules": [{
			"firewallrule": {
				"isallow": {"value": true},
				"enforced": {"value": true},
				"protocol": {"value": "udp"},
				"ports": [{"start": {"value": 3389}, "end": {"value": 3389}}],
			},
			"sourceranges": [{"value": "0.0.0.0/0"}],
		}],
	}}]}}}

	res := check.deny with input as inp
	res == set()
}
