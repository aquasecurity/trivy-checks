package builtin.google.sql.google0015_test

import rego.v1

import data.builtin.google.sql.google0015 as check
import data.lib.test

test_allow_tls_required if {
	inp := build_input({"requiretls": {"value": true}})
	res := check.deny with input as inp
	res == set()
}

test_deny_tls_not_required if {
	inp := build_input({"requiretls": {"value": false}})

	res := check.deny with input as inp
	count(res) == 1
}

build_input(ipconfig) := {"google": {"sql": {"instances": [{"settings": {"ipconfiguration": ipconfig}}]}}}
