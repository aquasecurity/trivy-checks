package builtin.azure.storage.azure0061_test

import rego.v1

import data.builtin.azure.storage.azure0061 as check
import data.lib.test

test_deny_cmk_not_configured_with_containers if {
	inp := {"azure": {"storage": {"accounts": [{"containers": [{"publicaccess": {"value": "private"}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_empty_key_vault_key_id_with_containers if {
	inp := {"azure": {"storage": {"accounts": [{
		"containers": [{"publicaccess": {"value": "private"}}],
		"customermanagedkey": {"keyvaultkeyid": {"value": ""}},
	}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_cmk_configured_with_containers if {
	inp := {"azure": {"storage": {"accounts": [{
		"containers": [{"publicaccess": {"value": "private"}}],
		"customermanagedkey": {"keyvaultkeyid": {"value": "https://keyvault.vault.azure.net/keys/mykey/version"}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_no_containers if {
	inp := {"azure": {"storage": {"accounts": [{"containers": []}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_account_without_containers if {
	inp := {"azure": {"storage": {"accounts": [{}]}}}

	test.assert_empty(check.deny) with input as inp
}
