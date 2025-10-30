package builtin.azure.storage.azure0059_test

import rego.v1

import data.builtin.azure.storage.azure0059 as check
import data.lib.test

test_deny_lrs_replication if {
	inp := {"azure": {"storage": {"accounts": [{"accountreplicationtype": {"value": "LRS"}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_zrs_replication if {
	inp := {"azure": {"storage": {"accounts": [{"accountreplicationtype": {"value": "ZRS"}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_replication_not_configured if {
	inp := {"azure": {"storage": {"accounts": [{}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_grs_replication if {
	inp := {"azure": {"storage": {"accounts": [{"accountreplicationtype": {"value": "GRS"}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_ragrs_replication if {
	inp := {"azure": {"storage": {"accounts": [{"accountreplicationtype": {"value": "RAGRS"}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_gzrs_replication if {
	inp := {"azure": {"storage": {"accounts": [{"accountreplicationtype": {"value": "GZRS"}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_ragzrs_replication if {
	inp := {"azure": {"storage": {"accounts": [{"accountreplicationtype": {"value": "RAGZRS"}}]}}}

	test.assert_empty(check.deny) with input as inp
}
