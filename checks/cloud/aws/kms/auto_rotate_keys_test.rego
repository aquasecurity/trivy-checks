package builtin.aws.kms.aws0065_test

import rego.v1

import data.builtin.aws.kms.aws0065 as check
import data.lib.test

test_allow_sign_verify_key_without_autorotate if {
	inp := {"aws": {"kms": {"keys": [{
		"usage": {"value": "SIGN_VERIFY"},
		"rotationenabled": {"value": false},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_encrypt_decrypt_key_with_autorotate if {
	inp := {"aws": {"kms": {"keys": [{
		"usage": {"value": "ENCRYPT_DECRYPT"},
		"rotationenabled": {"value": true},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_encrypt_decrypt_key_without_autorotate if {
	inp := {"aws": {"kms": {"keys": [{
		"usage": {"value": "ENCRYPT_DECRYPT"},
		"rotationenabled": {"value": false},
	}]}}}

	test.assert_equal_message("Key does not have rotation enabled.", check.deny) with input as inp
}
