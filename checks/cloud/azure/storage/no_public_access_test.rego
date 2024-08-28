package builtin.azure.storage.azure0007_test

import rego.v1

import data.builtin.azure.storage.azure0007 as check
import data.lib.test

test_deny_public_access_set_to_container if {
	inp := {"azure": {"storage": {"accounts": [{"containers": [{"publicaccess": {"value": "container"}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_public_access_set_to_off if {
	inp := {"azure": {"storage": {"accounts": [{"containers": [{"publicaccess": {"value": "off"}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
