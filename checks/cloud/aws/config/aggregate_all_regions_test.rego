package builtin.aws.config.aws0019_test

import rego.v1

import data.builtin.aws.config.aws0019 as check
import data.lib.test

test_allow_all_regions if {
	test.assert_empty(check.deny) with input as {"aws": {"config": {"configurationaggregrator": {"sourceallregions": {"value": true}}}}}
}

test_disallow_all_regions if {
	test.assert_equal_message("Configuration aggregation is not set to source from all regions.", check.deny) with input as {"aws": {"config": {"configurationaggregrator": {"sourceallregions": {"value": false}}}}}
}
