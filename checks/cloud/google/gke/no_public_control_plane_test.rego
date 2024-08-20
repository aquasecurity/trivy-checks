package builtin.google.gke.google0053_test

import rego.v1

import data.builtin.google.gke.google0053 as check
import data.lib.test

test_deny_master_auth_network_with_public_cidr if {
	inp := {"google": {"gke": {"clusters": [{"masterauthorizednetworks": {"cidrs": [{"value": "0.0.0.0/0"}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_master_auth_network_without_private_cidr if {
	inp := {"google": {"gke": {"clusters": [{"masterauthorizednetworks": {"cidrs": [{"value": "10.10.128.0/24"}]}}]}}}

	res := check.deny with input as inp
	res == set()
}
