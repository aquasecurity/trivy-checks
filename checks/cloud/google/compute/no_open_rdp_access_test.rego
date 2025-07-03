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
			},
			"sourceranges": [
				{"value": "0.0.0.0/0"},
				{"value": "1.2.3.4/32"},
			],
			"allowrules": [{
				"protocol": {"value": "tcp"},
				"ports": [{"value": "3389"}],
			}],
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
			},
			"sourceranges": [{"value": "1.2.3.4/32"}],
			"allowrules": [{
				"protocol": {"value": "tcp"},
				"ports": [{"value": "3389"}],
			}],
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
			},
			"sourceranges": [{"value": "0.0.0.0/0"}],
			"allowrules": [{
				"protocol": {"value": "tcp"},
				"ports": [{"value": "80"}],
			}],
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
			},
			"sourceranges": [{"value": "0.0.0.0/0"}],
			"allowrules": [{
				"protocol": {"value": "udp"},
				"ports": [{"value": "3389"}],
			}],
		}],
	}}]}}}

	res := check.deny with input as inp
	res == set()
}
