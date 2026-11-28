package builtin.azure.database.azure0021_test

import rego.v1

import data.builtin.azure.database.azure0021 as check

test_deny_psql_server_connection_throttling_disabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{"config": {"connectionthrottling": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_psql_server_connection_throttling_enabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{"config": {"connectionthrottling": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_psql_flexible_server_version_18_without_throttling if {
	inp := {"azure": {"database": {"postgresqlservers": [{
		"version": {"value": "18"},
		"config": {"connectionthrottling": {"value": false}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_deny_psql_flexible_server_version_17_throttling_disabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{
		"version": {"value": "17"},
		"config": {"connectionthrottling": {"value": false}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_psql_flexible_server_unknown_version_throttling_disabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{
		"version": {"value": ""},
		"config": {"connectionthrottling": {"value": false}},
	}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
