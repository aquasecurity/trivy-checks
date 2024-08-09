package builtin.aws.athena.aws0006_test

import rego.v1

import data.builtin.aws.athena.aws0006 as check
import data.lib.test

test_disallow_database_unencrypted if {
	inp := {"aws": {"athena": {"databases": [{"encryption": {"type": {"value": ""}}}]}}}
	test.assert_equal_message("Database does not have encryption configured.", check.deny) with input as inp
}

test_disallow_workgroup_unencrypted if {
	inp := {"aws": {"athena": {"workgroups": [{"encryption": {"type": {"value": ""}}}]}}}
	test.assert_equal_message("Workgroup does not have encryption configured.", check.deny) with input as inp
}

test_allow_database_encrypted if {
	inp := {"aws": {"athena": {"databases": [{"encryption": {"type": {"value": "SSE_S3"}}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_allow_workgroup_encrypted if {
	inp := {"aws": {"athena": {"workgroups": [{"encryption": {"type": {"value": "SSE_S3"}}}]}}}
	test.assert_empty(check.deny) with input as inp
}
