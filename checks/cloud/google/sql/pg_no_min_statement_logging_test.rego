package builtin.google.sql.google0021_test

import rego.v1

import data.builtin.google.sql.google0021 as check

test_deny_logging_enabled_for_all_statements if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logmindurationstatement": {"value": 1}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_logging_disabled_for_all_statements if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logmindurationstatement": {"value": -1}}},
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_logging_enabled_for_all_statements_for_non_postgres if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_8_0"},
		"settings": {"flags": {"logmindurationstatement": {"value": 1}}},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
