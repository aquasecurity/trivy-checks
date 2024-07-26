package builtin.nifcloud.computing.nifcloud0002_test

import rego.v1

import data.builtin.nifcloud.computing.nifcloud0002 as check
import data.lib.test

test_allow_sg_with_description if {
	inp := {"nifcloud": {"computing": {"securitygroups": [{"description": {"value": "Test"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_sg_without_description if {
	inp := {"nifcloud": {"computing": {"securitygroups": [{"description": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_sg_with_default_description if {
	inp := {"nifcloud": {"computing": {"securitygroups": [{"description": {"value": "Managed by Terraform"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
