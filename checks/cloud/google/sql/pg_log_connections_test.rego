package builtin.google.sql.google0016_test

import rego.v1

import data.builtin.google.sql.google0016 as check
import data.lib.test

test_deny_connections_logging_disabled if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logconnections": {"value": false}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_connections_logging_enabled if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logconnections": {"value": true}}},
	})

	check.deny with input as inp == set()
}

test_allow_connections_logging_disabled_for_non_postgres if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_8"},
		"settings": {"flags": {"logconnections": {"value": false}}},
	})

	check.deny with input as inp == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
