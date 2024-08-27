package builtin.digitalocean.compute.digitalocean0008_test

import rego.v1

import data.builtin.digitalocean.compute.digitalocean0008 as check
import data.lib.test

test_deny_auto_upgrade_disabled if {
	inp := {"digitalocean": {"compute": {"kubernetesclusters": [{"autoupgrade": {"value": false}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_auto_upgrade_enabled if {
	inp := {"digitalocean": {"compute": {"kubernetesclusters": [{"autoupgrade": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}
