package builtin.google.sql.google0014_test

import rego.v1

import data.builtin.google.sql.google0014 as check
import data.lib.test

test_deny_temp_files_logging_disabled_for_all_files if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logtempfilesize": {"value": -1}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_temp_files_logging_disabled_for_files_smaller_than_100kb if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logtempfilesize": {"value": 100}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_temp_files_logging_enabled_for_all_files if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"logtempfilesize": {"value": 0}}},
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_temp_files_logging_disabled_for_all_files_for_non_postgres if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_5_7"},
		"settings": {"flags": {"logtempfilesize": {"value": -1}}},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
