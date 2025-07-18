package builtin.google.compute.google0071_test

import rego.v1

import data.builtin.google.compute.google0071 as check

test_deny_ssh_access_from_anywhere if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
			"ports": [{"start": {"value": 22}, "end": {"value": 22}}],
		},
		"sourceranges": [{"value": "0.0.0.0/0"}],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ssh_access_from_specific_ip if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
			"ports": [{"start": {"value": 22}, "end": {"value": 22}}],
		},
		"sourceranges": [{"value": "192.168.1.0/24"}],
	}]}}]}}}

	res := check.deny with input as inp
	res == set()
}
