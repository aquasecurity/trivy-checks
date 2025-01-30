package builtin.aws.ecs.aws0034_test

import rego.v1

import data.builtin.aws.ecs.aws0034 as check
import data.lib.test

test_allow_cluster_with_container_insights if {
	inp := {"aws": {"ecs": {"clusters": [{"settings": {"containerinsightsmode": {"value": "enabled"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_cluster_with_enhanced_container_insights if {
	inp := {"aws": {"ecs": {"clusters": [{"settings": {"containerinsightsmode": {"value": "enhanced"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_cluster_without_container_insights if {
	inp := {"aws": {"ecs": {"clusters": [{"settings": {"containerinsightsmode": {"value": "disabled"}}}]}}}

	test.assert_equal_message("Cluster does not have container insights enabled.", check.deny) with input as inp
}
