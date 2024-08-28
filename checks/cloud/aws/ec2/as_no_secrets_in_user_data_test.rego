package builtin.aws.ec2.aws0129_test

import rego.v1

import data.builtin.aws.ec2.aws0129 as check
import data.lib.test

test_deny_launch_tmpl_with_sensitive_info if {
	inp := {"aws": {"ec2": {"launchtemplates": [{"instance": {"userdata": {"value": `
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2
`}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_launch_tmpl_without_sensitive_info if {
	inp := {"aws": {"ec2": {"launchtemplates": [{"instance": {"userdata": {"value": "export GREETING=hello"}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
