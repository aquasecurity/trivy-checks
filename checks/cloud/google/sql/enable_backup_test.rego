package builtin.google.sql.google0024_test

import rego.v1

import data.builtin.google.sql.google0024 as check
import data.lib.test

test_allow_backups_enabled if {
	inp := build_input({
		"isreplica": {"value": false},
		"settings": {"backups": {"enabled": {"value": true}}},
	})

	res := check.deny with input as inp
	res == set()
}

test_deny_backups_disabled if {
	inp := build_input({
		"isreplica": {"value": false},
		"settings": {"backups": {"enabled": {"value": false}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_backups_disabled_for_replica if {
	inp := build_input({
		"isreplica": {"value": true},
		"settings": {"backups": {"enabled": {"value": false}}},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
