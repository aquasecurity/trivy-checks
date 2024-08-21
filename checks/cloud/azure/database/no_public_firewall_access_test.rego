package builtin.azure.database.azure0029_test

import rego.v1

import data.builtin.azure.database.azure0029 as check
import data.lib.test

test_deny_mysql_server_allow_public_access if {
	inp := {"azure": {"database": {"mysqlservers": [{"server": {"firewallrules": [{
		"startip": {"value": "0.0.0.0"},
		"endip": {"value": "255.255.255.255"},
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_mysql_server_allow_single_public_access if {
	inp := {"azure": {"database": {"mysqlservers": [{"server": {"firewallrules": [{
		"startip": {"value": "8.8.8.8"},
		"endip": {"value": "8.8.8.8"},
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_mysql_server_allow_access_to_azure_services if {
	inp := {"azure": {"database": {"mysqlservers": [{"server": {"firewallrules": [{
		"startip": {"value": "0.0.0.0"},
		"endip": {"value": "0.0.0.0"},
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
