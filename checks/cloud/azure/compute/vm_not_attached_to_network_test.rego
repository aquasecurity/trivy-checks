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

test_deny_linux_vm_no_security_group_field_absent if {
	res := check.deny with input as build_linux_input_no_nsg_field_absent
	count(res) == 1
}

test_deny_windows_vm_no_security_group_field_absent if {
	res := check.deny with input as build_windows_input_no_nsg_field_absent
	count(res) == 1
}

build_linux_input_no_nsg := {"azure": {"compute": {"linuxvirtualmachines": [{"virtualmachine": {"networkinterfaces": [{"securitygroups": []}]}}]}}}

build_linux_input_with_nsg := {"azure": {"compute": {"linuxvirtualmachines": [{"virtualmachine": {"networkinterfaces": [{"securitygroups": [{"__defsec_metadata": {}, "rules": []}]}]}}]}}}

build_windows_input_no_nsg := {"azure": {"compute": {"windowsvirtualmachines": [{"virtualmachine": {"networkinterfaces": [{"securitygroups": []}]}}]}}}

build_windows_input_with_nsg := {"azure": {"compute": {"windowsvirtualmachines": [{"virtualmachine": {"networkinterfaces": [{"securitygroups": [{"__defsec_metadata": {}, "rules": []}]}]}}]}}}

build_linux_input_no_nsg_field_absent := {"azure": {"compute": {"linuxvirtualmachines": [{"virtualmachine": {"networkinterfaces": [{}]}}]}}}

build_windows_input_no_nsg_field_absent := {"azure": {"compute": {"windowsvirtualmachines": [{"virtualmachine": {"networkinterfaces": [{}]}}]}}}
