package lib.aws.actions_test

import rego.v1

import data.lib.aws.actions

test_is_wildcard_denied_action_allowed if {
	actions.is_wildcard_denied(["s3:foo"]) with actions.actions_without_resource_level_support as {"s3:bar"}
}

test_is_wildcard_denied_action_denied if {
	not actions.is_wildcard_denied(["s3:foo"]) with actions.actions_without_resource_level_support as {"s3:foo"}
}
