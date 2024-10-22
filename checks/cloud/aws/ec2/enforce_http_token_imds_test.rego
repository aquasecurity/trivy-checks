package builtin.aws.ec2.aws0028_test

import rego.v1

import data.builtin.aws.ec2.aws0028 as check
import data.lib.test

test_allow_instance_with_tokens if {
	inp := build_input({
		"httptokens": {"value": "required"},
		"httpendpoint": {"value": "enabled"},
	})

	test.assert_empty(check.deny) with input as inp
}

test_deny_instance_without_tokens if {
	inp := build_input({
		"httptokens": {"value": "disabled"},
		"httpendpoint": {"value": "enabled"},
	})

	test.assert_equal_message("Instance does not require IMDS access to require a token", check.deny) with input as inp
}

test_allow_instance_with_endpoint_disabled if {
	inp := build_input({
		"httptokens": {"value": "disabled"},
		"httpendpoint": {"value": "disabled"},
	})

	test.assert_empty(check.deny) with input as inp
}

build_input(meta_opts) := {"aws": {"ec2": {"instances": [{"metadataoptions": meta_opts}]}}}

test_allow_instance_with_tokens_unresolvable if {
	inp := build_input({
		"httptokens": {"value": "", "unresolvable": true},
		"httpendpoint": {"value": "enabled"},
	})

	test.assert_empty(check.deny) with input as inp
}
