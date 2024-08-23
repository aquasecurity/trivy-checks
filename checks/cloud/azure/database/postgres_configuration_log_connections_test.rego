package builtin.azure.database.azure0019_test

import rego.v1

import data.builtin.azure.database.azure0019 as check
import data.lib.test

test_deny_psql_server_connection_logconnections_disabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{"config": {"logconnections": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_psql_server_connection_logconnections_enabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{"config": {"logconnections": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
