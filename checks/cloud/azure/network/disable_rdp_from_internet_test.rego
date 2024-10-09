package builtin.azure.network.azure0048_test

import rego.v1

import data.builtin.azure.network.azure0048 as check
import data.lib.test

test_deny_inbound_rule_allows_rdp_access_from_internet if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"outbound": {"value": false},
		"allow": {"value": true},
		"protocol": {"value": "Tcp"},
		"sourceaddresses": [{"value": "*"}],
		"destinationports": [{
			"start": {"value": 3310},
			"end": {"value": 3390},
		}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_inbound_rule_allow_rdp_access_from_specific_address if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"outbound": {"value": false},
		"allow": {"value": true},
		"protocol": {"value": "Tcp"},
		"sourceaddresses": [{"value": "237.84.2.178"}],
		"destinationports": [{
			"start": {"value": 3310},
			"end": {"value": 3390},
		}],
	}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_inbound_rule_allow_access_for_icmp if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"outbound": {"value": false},
		"allow": {"value": true},
		"protocol": {"value": "Icmp"},
		"sourceaddresses": [{"value": "*"}],
		"destinationports": [{
			"start": {"value": 3310},
			"end": {"value": 3390},
		}],
	}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_inbound_rule_allow_access_for_non_rdp_port if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"outbound": {"value": false},
		"allow": {"value": true},
		"protocol": {"value": "Icmp"},
		"sourceaddresses": [{"value": "*"}],
		"destinationports": [{
			"start": {"value": 8080},
			"end": {"value": 8080},
		}],
	}]}]}}}

	res := check.deny with input as inp
	res == set()
}
