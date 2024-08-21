package builtin.azure.database.azure0026_test

import rego.v1

import data.builtin.azure.database.azure0026 as check
import data.lib.test

test_deny_msql_server_minimum_tls_version_is_1_0 if {
	inp := {"azure": {"database": {"mssqlservers": [build_server("1.0")]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_mysql_server_minimum_tls_version_is_1_0 if {
	inp := {"azure": {"database": {"mysqlservers": [build_server("TLS1_0")]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_postgresql_server_minimum_tls_version_is_1_0 if {
	inp := {"azure": {"database": {"postgresqlservers": [build_server("TLS1_0")]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_servers_with_minimum_tls_version_1_2 if {
	inp := {"azure": {"database": {
		"mssqlservers": [build_server(check.recommended_mssql_tls_version)],
		"mysqlservers": [build_server(check.recommended_tls_version)],
		"postgresqlservers": [build_server(check.recommended_tls_version)],
	}}}

	res := check.deny with input as inp
	count(res) == 0
}

build_server(ver) := {"server": {"minimumtlsversion": {"value": ver}}}
