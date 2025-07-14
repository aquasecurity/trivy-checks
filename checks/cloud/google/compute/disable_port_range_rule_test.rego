package builtin.google.compute.google0074_test

import rego.v1

import data.builtin.google.compute.google0074 as check

test_deny_large_port_range if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{"firewallrule": {"ports": [{
		"start": {"value": 8000},
		"end": {"value": (8000 + check.max_port_range_size) + 1}, # 21 ports (exceeds limit)
	}]}}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_small_port_range if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{"firewallrule": {"ports": [{
		"start": {"value": 8000},
		"end": {"value": (8000 + check.max_port_range_size) - 1}, # 19 ports (within limit)
	}]}}]}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_exact_threshold if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{"firewallrule": {"ports": [{
		"start": {"value": 8000},
		"end": {"value": 8000 + check.max_port_range_size}, # 20 ports (exactly at limit)
	}]}}]}}]}}}

	res := check.deny with input as inp
	res == set()
}
