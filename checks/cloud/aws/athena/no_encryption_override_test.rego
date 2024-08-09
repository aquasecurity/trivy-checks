package builtin.aws.athena.aws0007_test

import rego.v1

import data.builtin.aws.athena.aws0007 as check
import data.lib.test

test_allow_workgroup_enforce_configuration if {
	inp := {"aws": {"athena": {"workgroups": [{"enforceconfiguration": {"value": true}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_workgroup_no_enforce_configuration if {
	inp := {"aws": {"athena": {"workgroups": [{"enforceconfiguration": {"value": false}}]}}}
	test.assert_equal_message("The workgroup configuration is not enforced.", check.deny) with input as inp
}
