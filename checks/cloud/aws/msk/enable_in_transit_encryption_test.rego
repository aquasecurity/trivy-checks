package builtin.aws.msk.aws0073_test

import rego.v1

import data.builtin.aws.msk.aws0073 as check
import data.lib.test

test_deny_broker_with_plaintext_encryption if {
	inp := {"aws": {"msk": {"clusters": [{"encryptionintransit": {"clientbroker": {"value": check.plaintext}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_broker_with_tls_plaintext_encryption if {
	inp := {"aws": {"msk": {"clusters": [{"encryptionintransit": {"clientbroker": {"value": check.tls_plaintext}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_broker_with_tls_encryption if {
	inp := {"aws": {"msk": {"clusters": [{"encryptionintransit": {"clientbroker": {"value": "TLS"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
