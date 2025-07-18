package builtin.google.sql.google0019_test

import rego.v1

import data.builtin.google.sql.google0019 as check

test_deny_cross_database_ownership_chaining_enabled if {
	inp := build_input({
		"databaseversion": {"value": "SQLSERVER_2017_STANDARD"},
		"settings": {"flags": {"crossdbownershipchaining": {"value": true}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_cross_database_ownership_chaining_disabled if {
	inp := build_input({
		"databaseversion": {"value": "SQLSERVER_2017_STANDARD"},
		"settings": {"flags": {"crossdbownershipchaining": {"value": false}}},
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_cross_database_ownership_chaining_enabled_for_non_sql_servers if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_15"},
		"settings": {"flags": {"crossdbownershipchaining": {"value": true}}},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
