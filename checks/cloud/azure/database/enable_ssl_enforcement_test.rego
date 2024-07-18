package builtin.azure.database.azure0020_test

import rego.v1

import data.builtin.azure.database.azure0020 as check
import data.lib.test

test_deny_maria_db_server_ssl_not_enforced if {
	inp := {"azure": {"database": {"mariadbservers": [{"server": {"enablesslenforcement": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_mysql_db_server_ssl_not_enforced if {
	inp := {"azure": {"database": {"mysqlservers": [{"server": {"enablesslenforcement": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_postgresql_db_server_ssl_not_enforced if {
	inp := {"azure": {"database": {"postgresqlservers": [{"server": {}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_servers_with_enforced_ssl if {
	inp := {"azure": {"database": {
		"mariadbservers": [{"server": {"enablesslenforcement": {"value": true}}}],
		"mysqlservers": [{"server": {"enablesslenforcement": {"value": true}}}],
		"postgresqlservers": [{"server": {"enablesslenforcement": {"value": true}}}],
	}}}

	res := check.deny with input as inp
	count(res) == 0
}
