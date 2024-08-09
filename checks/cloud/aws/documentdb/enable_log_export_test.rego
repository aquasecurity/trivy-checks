package builtin.aws.documentdb.aws0020_test

import rego.v1

import data.builtin.aws.documentdb.aws0020 as check
import data.lib.test

test_disallow_no_export_log if {
	inp := {"aws": {"documentdb": {"clusters": [{"enabledlogexports": []}]}}}
	test.assert_equal_message("Neither CloudWatch audit nor profiler log exports are enabled.", check.deny) with input as inp
}

test_allow_export_audit if {
	inp := {"aws": {"documentdb": {"clusters": [{"enabledlogexports": [{"value": "audit"}]}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_allow_export_profiler if {
	inp := {"aws": {"documentdb": {"clusters": [{"enabledlogexports": [{"value": "profiler"}]}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_allow_export_mixed if {
	inp := {"aws": {"documentdb": {"clusters": [{"enabledlogexports": [{"value": "audit"}, {"value": "profiler"}]}]}}}
	test.assert_empty(check.deny) with input as inp
}
