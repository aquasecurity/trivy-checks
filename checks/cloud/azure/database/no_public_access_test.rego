package builtin.azure.database.azure0022_test

import rego.v1

import data.builtin.azure.database.azure0022 as check
import data.lib.test

test_deny_mysql_server_public_access_enabled if {
	res := check.deny with input as build_input("mysqlservers", true)
	count(res) == 1
}

test_deny_mssql_server_public_access_enabled if {
	res := check.deny with input as build_input("mssqlservers", true)
	count(res) == 1
}

test_deny_mariadb_server_public_access_enabled if {
	res := check.deny with input as build_input("mariadbservers", true)
	count(res) == 1
}

test_deny_postgresql_server_public_access_enabled if {
	res := check.deny with input as build_input("postgresqlservers", true)
	count(res) == 1
}

test_allow_servers_public_access_disabled if {
	inp := {"azure": {"database": {
		"mysqlservers": [{"server": {"enablepublicnetworkaccess": {"value": false}}}],
		"mssqlservers": [{"server": {"enablepublicnetworkaccess": {"value": false}}}],
		"mariadbservers": [{"server": {"enablepublicnetworkaccess": {"value": false}}}],
		"postgresqlservers": [{"server": {"enablepublicnetworkaccess": {"value": false}}}],
	}}}
	res := check.deny with input as inp
	count(res) == 0
}

build_input(db_type, public_access) := {"azure": {"database": {db_type: [{"server": {"enablepublicnetworkaccess": {"value": public_access}}}]}}}
