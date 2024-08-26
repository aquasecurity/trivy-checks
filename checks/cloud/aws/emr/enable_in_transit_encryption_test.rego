package builtin.aws.emr.aws0138_test

import rego.v1

import data.builtin.aws.emr.aws0138 as check
import data.lib.test

test_allow_with_encryption if {
	inp := {"aws": {"emr": {"securityconfiguration": [{"configuration": {"value": json.marshal({"EncryptionConfiguration": {"EnableInTransitEncryption": true}})}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_encryption if {
	inp := {"aws": {"emr": {"securityconfiguration": [{"configuration": {"value": json.marshal({"EncryptionConfiguration": {"EnableInTransitEncryption": false}})}}]}}}

	test.assert_equal_message("EMR cluster does not have in-transit encryption enabled.", check.deny) with input as inp
}
