package builtin.aws.efs.aws0037_test

import rego.v1

import data.builtin.aws.efs.aws0037 as check
import data.lib.test

test_allow_fs_encrypted if {
	inp := {"aws": {"efs": {"filesystems": [{"encrypted": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_fs_unencrypted if {
	inp := {"aws": {"efs": {"filesystems": [{"encrypted": {"value": false}}]}}}

	test.assert_equal_message("File system is not encrypted.", check.deny) with input as inp
}
