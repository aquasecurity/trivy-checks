package builtin.google.sql.google0018_test

import rego.v1

import data.builtin.google.sql.google0018 as check
import data.lib.test

test_deny_minimum_log_level_is_not_error if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logminmessages": {"value": "PANIC"}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_minimum_log_level_is_error if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logminmessages": {"value": "ERROR"}}},
	})

	check.deny with input as inp == set()
}

test_allow_minimum_log_level_is_not_error_for_non_postgres if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_5_7"},
		"settings": {"flags": {"logminmessages": {"value": "PANIC"}}},
	})

	check.deny with input as inp == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
