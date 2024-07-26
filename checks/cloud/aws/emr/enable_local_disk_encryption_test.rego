package builtin.aws.emr.aws0139_test

import rego.v1

import data.builtin.aws.emr.aws0139 as check
import data.lib.test

test_allow_with_encryption if {
	inp := {"aws": {"emr": {"securityconfiguration": [{"configuration": {"value": json.marshal({"EncryptionConfiguration": {"AtRestEncryptionConfiguration": {"LocalDiskEncryptionConfiguration": {"EncryptionKeyProviderType": "AwsKms"}}}})}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_encryption if {
	inp := {"aws": {"emr": {"securityconfiguration": [{"configuration": {"value": json.marshal({"EncryptionConfiguration": {"AtRestEncryptionConfiguration": {"LocalDiskEncryptionConfiguration": {"EncryptionKeyProviderType": ""}}}})}}]}}}

	test.assert_equal_message("EMR cluster does not have in-transit encryption enabled.", check.deny) with input as inp
}
