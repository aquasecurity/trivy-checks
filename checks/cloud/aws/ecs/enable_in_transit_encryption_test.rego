package builtin.aws.ecs.aws0035_test

import rego.v1

import data.builtin.aws.ecs.aws0035 as check
import data.lib.test

test_allow_in_transit_encryption_enabled if {
	inp := {"aws": {"ecs": {"taskdefinitions": [{"volumes": [{"efsvolumeconfiguration": {"transitencryptionenabled": {"value": true}}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_in_transit_encryption_disabled if {
	inp := {"aws": {"ecs": {"taskdefinitions": [{"volumes": [{"efsvolumeconfiguration": {"transitencryptionenabled": {"value": false}}}]}]}}}

	test.assert_equal_message("Task definition includes a volume which does not have in-transit-encryption enabled.", check.deny) with input as inp
}
