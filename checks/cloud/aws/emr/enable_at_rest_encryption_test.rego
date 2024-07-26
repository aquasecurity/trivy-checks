package builtin.aws.emr.aws0137_test

import rego.v1

import data.builtin.aws.emr.aws0137 as check
import data.lib.test

test_allow_with_encryption if {
	inp := {"aws": {"emr": {"securityconfiguration": [{"configuration": {"value": json.marshal({"EncryptionConfiguration": {"EnableAtRestEncryption": true}})}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_encryption if {
	inp := {"aws": {"emr": {"securityconfiguration": [{"configuration": {"value": json.marshal({"EncryptionConfiguration": {"EnableAtRestEncryption": false}})}}]}}}

	test.assert_equal_message("EMR cluster does not have at-rest encryption enabled.", check.deny) with input as inp
}
