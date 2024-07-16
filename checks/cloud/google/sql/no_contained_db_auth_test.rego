package builtin.google.sql.google0023_test

import rego.v1

import data.builtin.google.sql.google0023 as check
import data.lib.test

test_allow_db_auth_disabled if {
	inp := build_input({
		"databaseversion": {"value": "SQLSERVER_2017_STANDARD"},
		"settings": {"flags": {"containeddatabaseauthentication": {"value": false}}},
	})

	check.deny with input as inp == set()
}

test_deny_db_auth_enabled if {
	inp := build_input({
		"databaseversion": {"value": "SQLSERVER_2017_STANDARD"},
		"settings": {"flags": {"containeddatabaseauthentication": {"value": true}}},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_db_auth_enabled_for_non_sqlserver if {
	inp := build_input({
		"databaseversion": {"value": "MYSQL_5_7"},
		"settings": {"flags": {"containeddatabaseauthentication": {"value": true}}},
	})

	check.deny with input as inp == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
