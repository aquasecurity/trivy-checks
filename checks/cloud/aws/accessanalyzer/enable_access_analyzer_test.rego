package builtin.aws.accessanalyzer.aws0175_test

import rego.v1

import data.builtin.aws.accessanalyzer.aws0175 as check
import data.lib.test

test_disallow_no_analyzers if {
	r := check.deny with input as {"aws": {"accessanalyzer": {"analyzers": []}}}
	test.assert_equal_message("Access Analyzer is not enabled.", r)
}

test_disallow_analyzer_disabled if {
	r := check.deny with input as {"aws": {"accessanalyzer": {"analyzers": [{"active": {"value": false}}]}}}
	test.assert_equal_message("Access Analyzer is not enabled.", r)
}

test_allow_one_of_analyzer_disabled if {
	r := check.deny with input as {"aws": {"accessanalyzer": {"analyzers": [{"active": {"value": false}}, {"active": {"value": true}}]}}}
	test.assert_empty(r)
}

test_allow_analyzer_enabled if {
	r := check.deny with input as {"aws": {"accessanalyzer": {"analyzers": [{"active": {"value": true}}]}}}
	test.assert_empty(r)
}
