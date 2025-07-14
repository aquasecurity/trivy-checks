package builtin.google.sql.google0020_test

import rego.v1

import data.builtin.google.sql.google0020 as check

test_deny_lock_waits_loggging_disabled if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"loglockwaits": {"value": false}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_lock_waits_loggging_enabled if {
	inp := build_input({
		"databaseversion": {"value": "POSTGRES_12"},
		"settings": {"flags": {"loglockwaits": {"value": true}}},
	})

	res := check.deny with input as inp
	res == set()
}

test_allow_lock_waits_loggging_disabled_for_non_postgres if {
	inp := build_input({
		"databaseversion": {"value": "SQLSERVER_2017_STANDARD"},
		"settings": {"flags": {"loglockwaits": {"value": false}}},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
