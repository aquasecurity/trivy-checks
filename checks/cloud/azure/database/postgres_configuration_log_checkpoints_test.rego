package builtin.azure.database.azure0024_test

import rego.v1

import data.builtin.azure.database.azure0024 as check
import data.lib.test

test_deny_psql_server_connection_logcheckpoints_disabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{"config": {"logcheckpoints": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_psql_server_connection_logcheckpoints_enabled if {
	inp := {"azure": {"database": {"postgresqlservers": [{"config": {"logcheckpoints": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
