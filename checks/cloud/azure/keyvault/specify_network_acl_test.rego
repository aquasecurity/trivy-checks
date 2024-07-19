package builtin.azure.keyvault.azure0013_test

import rego.v1

import data.builtin.azure.keyvault.azure0013 as check
import data.lib.test

test_deny_acl_default_action_is_allow if {
	res := check.deny with input as build_input("Allow")
	count(res) == 1
}

test_allow_acl_default_action_is_deny if {
	res := check.deny with input as build_input("Deny")
	count(res) == 0
}

build_input(action) := {"azure": {"keyvault": {"vaults": [{"networkacls": {"defaultaction": {"value": action}}}]}}}
