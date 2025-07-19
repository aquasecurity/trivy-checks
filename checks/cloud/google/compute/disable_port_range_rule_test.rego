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

test_check_port_range_custom_limits[name] if {
	some name, tc in {
		"exceeds default limit": {
			"start_port": 8000,
			"end_port": 8035, # 35 ports (exceeds default 30)
			"custom_limit": null,
			"expected": 1,
		},
		"within default limit": {
			"start_port": 8000,
			"end_port": 8025, # 25 ports (within default 30)
			"custom_limit": null,
			"expected": 0,
		},
		"exceeds custom limit": {
			"start_port": 8000,
			"end_port": 8015, # 15 ports (exceeds custom 10)
			"custom_limit": 10,
			"expected": 1,
		},
		"invalid custom input": {
			"start_port": 8000,
			"end_port": 8015, # 15 ports (within default 30, exceeds custom)
			"custom_limit": -10,
			"expected": 0,
		},
	}

	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{"firewallrule": {"ports": [{
		"start": {"value": tc.start_port},
		"end": {"value": tc.end_port},
	}]}}]}}]}}}

	res := check.deny with input as inp
		with data.gcp0074.max_port_range_size as tc.custom_limit

	count(res) == tc.expected
}
