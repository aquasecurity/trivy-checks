package builtin.azure.network.azure0074_test

import rego.v1

import data.builtin.azure.network.azure0074 as check

test_deny_sensitive_port_exposed_to_all if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": false},
		"protocol": {"value": "TCP"},
		"destinationports": [{
			"start": {"value": 23},
			"end": {"value": 23},
		}],
		"sourceaddresses": [{"value": "0.0.0.0/0"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_sensitive_port_range_exposed if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": false},
		"protocol": {"value": "TCP"},
		"destinationports": [{
			"start": {"value": 20},
			"end": {"value": 25},
		}],
		"sourceaddresses": [{"value": "*"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) > 0
}

test_allow_non_sensitive_port if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": false},
		"protocol": {"value": "TCP"},
		"destinationports": [{
			"start": {"value": 8080},
			"end": {"value": 8080},
		}],
		"sourceaddresses": [{"value": "0.0.0.0/0"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_sensitive_port_restricted_source if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": false},
		"protocol": {"value": "TCP"},
		"destinationports": [{
			"start": {"value": 23},
			"end": {"value": 23},
		}],
		"sourceaddresses": [{"value": "10.0.0.0/8"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
