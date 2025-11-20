package builtin.azure.compute.azure0068_test

import rego.v1

import data.builtin.azure.compute.azure0068 as check

test_deny_linux_vm_no_security_group if {
	res := check.deny with input as build_linux_input_no_nsg
	count(res) == 1
}

test_allow_linux_vm_with_security_group if {
	res := check.deny with input as build_linux_input_with_nsg
	count(res) == 0
}

test_deny_windows_vm_no_security_group if {
	res := check.deny with input as build_windows_input_no_nsg
	count(res) == 1
}

test_allow_windows_vm_with_security_group if {
	res := check.deny with input as build_windows_input_with_nsg
	count(res) == 0
}


build_linux_input_no_nsg := {"azure": {"compute": {"linuxvirtualmachines": [{
	"__defsec_metadata": {"managed": true},
	"virtualmachine": {"networkinterfaces": [{"securitygroups": []}]},
}]}}}

build_linux_input_with_nsg := {"azure": {"compute": {"linuxvirtualmachines": [{
	"__defsec_metadata": {"managed": true},
	"virtualmachine": {"networkinterfaces": [{"securitygroups": [{"name": "test-nsg"}]}]},
}]}}}

build_windows_input_no_nsg := {"azure": {"compute": {"windowsvirtualmachines": [{
	"__defsec_metadata": {"managed": true},
	"virtualmachine": {"networkinterfaces": [{"securitygroups": []}]},
}]}}}

build_windows_input_with_nsg := {"azure": {"compute": {"windowsvirtualmachines": [{
	"__defsec_metadata": {"managed": true},
	"virtualmachine": {"networkinterfaces": [{"securitygroups": [{"name": "test-nsg"}]}]},
}]}}}
