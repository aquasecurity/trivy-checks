package builtin.azure.keyvault.azure0015_test

import rego.v1

import data.builtin.azure.keyvault.azure0015 as check
import data.lib.test

test_deny_secret_wihout_content_type if {
	res := check.deny with input as build_input("")
	count(res) == 1
}

test_allow_secret_with_content_type if {
	res := check.deny with input as build_input("password")
	res == set()
}

build_input(content_type) := {"azure": {"keyvault": {"vaults": [{"secrets": [{"contenttype": {"value": content_type}}]}]}}}
