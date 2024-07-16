package builtin.google.sql.google0026_test

import rego.v1

import data.builtin.google.sql.google0026 as check
import data.lib.test

test_deny_local_file_read_access_enabled if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_5_7"},
		"settings": {"flags": {"localinfile": {"value": true}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_local_file_read_access_disabled if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_5_7"},
		"settings": {"flags": {"localinfile": {"value": false}}},
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_local_file_read_access_enabled_for_non_mysql if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_9_6"},
		"settings": {"flags": {"localinfile": {"value": true}}},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
