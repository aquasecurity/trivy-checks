package builtin.aws.documentdb.aws0022_test

import rego.v1

import data.builtin.aws.documentdb.aws0022 as check
import data.lib.test

test_allow_cluster_with_kms_key if {
	inp := {"aws": {"documentdb": {"clusters": [{"kmskeyid": {"value": "test"}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_instance_with_kms_key if {
	inp := {"aws": {"documentdb": {"clusters": [{"instances": [{"kmskeyid": {"value": "test"}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_cluster_without_kms_key if {
	inp := {"aws": {"documentdb": {"clusters": [{"kmskeyid": {"value": ""}}]}}}

	test.assert_equal_message("Cluster encryption does not use a customer-managed KMS key.", check.deny) with input as inp
}

test_disallow_instance_without_kms_key if {
	inp := {"aws": {"documentdb": {"clusters": [{"instances": [{"kmskeyid": {"value": ""}}]}]}}}

	test.assert_equal_message("Instance encryption does not use a customer-managed KMS key.", check.deny) with input as inp
}
