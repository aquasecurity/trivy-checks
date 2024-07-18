package builtin.azure.compute.azure0039_test

import rego.v1

import data.builtin.azure.compute.azure0039 as check
import data.lib.test

test_deny_linux_vm_password_auth_enabled if {
	res := check.deny with input as build_input(false)
	count(res) == 1
}

test_allow_linux_vm_password_auth_disabled if {
	res := check.deny with input as build_input(true)
	count(res) == 0
}

build_input(disable_auth) := {"azure": {"compute": {"linuxvirtualmachines": [{"osprofilelinuxconfig": {"disablepasswordauthentication": {"value": disable_auth}}}]}}}
