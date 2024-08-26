package builtin.nifcloud.nas.nifcloud0015_test

import rego.v1

import data.builtin.nifcloud.nas.nifcloud0015 as check
import data.lib.test

test_allow_sg_with_description if {
	res := check.deny with input as build_input("Test")
	res == set()
}

test_deny_sg_without_description if {
	res := check.deny with input as build_input("")
	count(res) == 1
}

test_deny_sg_with_default_description if {
	res := check.deny with input as build_input("Managed by Terraform")
	count(res) == 1
}

build_input(description) := {"nifcloud": {"nas": {"nassecuritygroups": [{"description": {"value": description}}]}}}
