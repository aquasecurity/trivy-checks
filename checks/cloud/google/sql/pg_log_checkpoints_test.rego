package builtin.google.sql.google0025_test

import rego.v1

import data.builtin.google.sql.google0025 as check
import data.lib.test

test_deny_log_checkpoints_disabled if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_9_6"},
		"settings": {"flags": {"logcheckpoints": {"value": false}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_log_checkpoints_enabled if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_9_6"},
		"settings": {"flags": {"logcheckpoints": {"value": true}}},
	})

	check.deny with input as inp == set()
}

test_allow_log_checkpoints_disabled_for_non_postgres if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_5_7"},
		"settings": {"flags": {"logcheckpoints": {"value": false}}},
	})

	check.deny with input as inp == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
