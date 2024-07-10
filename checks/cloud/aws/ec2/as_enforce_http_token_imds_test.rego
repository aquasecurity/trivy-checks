package builtin.aws.ec2.aws0130_test

import rego.v1

import data.builtin.aws.ec2.aws0130 as check
import data.lib.test

test_allow_launch_config_with_tokens if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"metadataoptions": {
		"httptokens": {"value": "required"},
		"httpendpoint": {"value": "enabled"},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_launch_template_with_tokens if {
	inp := {"aws": {"ec2": {"launchtemplates": [{"instance": {"metadataoptions": {
		"httptokens": {"value": "required"},
		"httpendpoint": {"value": "enabled"},
	}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_launch_config_without_tokens_but_endpoint_disabled if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"metadataoptions": {
		"httptokens": {"value": "optional"},
		"httpendpoint": {"value": "disabled"},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_launch_config_without_tokens if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"metadataoptions": {
		"httptokens": {"value": "disabled"},
		"httpendpoint": {"value": "enabled"},
	}}]}}}

	test.assert_equal_message("Launch configuration does not require IMDS access to require a token", check.deny) with input as inp
}

test_deny_launch_template_without_tokens if {
	inp := {"aws": {"ec2": {"launchtemplates": [{"instance": {"metadataoptions": {
		"httptokens": {"value": "disabled"},
		"httpendpoint": {"value": "enabled"},
	}}}]}}}

	test.assert_equal_message("Launch template does not require IMDS access to require a token", check.deny) with input as inp
}
