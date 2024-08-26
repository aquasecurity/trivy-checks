package builtin.aws.sam.aws0110_test

import rego.v1

import data.builtin.aws.sam.aws0110 as check
import data.lib.test

test_deny_api_unencrypted_cache if {
	inp := {"aws": {"sam": {"apis": [{"restmethodsettings": {"cachedataencrypted": {"value": false}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_api_encrypted_cache if {
	inp := {"aws": {"sam": {"apis": [{"restmethodsettings": {"cachedataencrypted": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
