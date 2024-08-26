package builtin.google.sql.google0021_test

import rego.v1

import data.builtin.google.sql.google0021 as check
import data.lib.test

test_deny_logging_enabled_for_all_statements if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logmindurationstatement": {"value": true}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_logging_disabled_for_all_statements if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logmindurationstatement": {"value": false}}},
	})

	check.deny with input as inp == set()
}

test_allow_logging_enabled_for_all_statements_for_non_postgres if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_8_0"},
		"settings": {"flags": {"logmindurationstatement": {"value": true}}},
	})

	check.deny with input as inp == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
