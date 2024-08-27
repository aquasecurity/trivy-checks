package builtin.digitalocean.compute.digitalocean0005_test

import rego.v1

import data.builtin.digitalocean.compute.digitalocean0005 as check
import data.lib.test

test_deny_surge_upgrade_disabled if {
	inp := {"digitalocean": {"compute": {"kubernetesclusters": [{"surgeupgrade": {"value": false}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_surge_upgrade_enabled if {
	inp := {"digitalocean": {"compute": {"kubernetesclusters": [{"surgeupgrade": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}
