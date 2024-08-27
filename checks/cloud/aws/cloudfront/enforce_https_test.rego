package builtin.aws.cloudfront.aws0012_test

import rego.v1

import data.builtin.aws.cloudfront.aws0012 as check
import data.lib.test

test_deny_default_cache_behavior_with_allow_all if {
	r := check.deny with input as build_input({"defaultcachebehaviour": {"viewerprotocolpolicy": {"value": "allow-all"}}})
	test.assert_equal_message("Distribution allows unencrypted communications.", r)
}

test_deny_ordered_cache_behaviors_with_allow_all if {
	r := check.deny with input as build_input({"orderercachebehaviours": [{"viewerprotocolpolicy": {"value": "allow-all"}}]})
	test.assert_equal_message("Distribution allows unencrypted communications.", r)
}

test_allow_default_cache_behavior_with_https if {
	inp := build_input({"defaultcachebehavior": {"viewerprotocolpolicy": {"value": "https-only"}}})
	test.assert_empty(check.deny) with input as inp
}

test_allow_ordered_cache_behaviors_with_https if {
	inp := build_input({"orderercachebehaviours": [{"viewerprotocolpolicy": {"value": "https-only"}}]})
	test.assert_empty(check.deny) with input as inp
}

build_input(body) = {"aws": {"cloudfront": {"distributions": [body]}}}
