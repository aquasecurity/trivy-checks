package builtin.nifcloud.rdb.nifcloud0012_test

import rego.v1

import data.builtin.nifcloud.rdb.nifcloud0012 as check
import data.lib.test

test_allow_sg_with_description if {
	inp := {"nifcloud": {"rdb": {"dbsecuritygroups": [{"description": {"value": "Test"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_sg_with_default_description if {
	inp := {"nifcloud": {"rdb": {"dbsecuritygroups": [{"description": {"value": "Managed by Terraform"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_sg_without_description if {
	inp := {"nifcloud": {"rdb": {"dbsecuritygroups": [{"description": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
