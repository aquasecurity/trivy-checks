package builtin.google.kms.google0065_test

import rego.v1

import data.builtin.google.kms.google0065 as check
import data.lib.test

test_deny_key_rotation_period_greather_than_90_days if {
	inp := {"google": {"kms": {"keyrings": [{"keys": [{"rotationperiodseconds": {"value": 7862400}}]}]}}} # 91 days

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_key_rotation_period_less_than_90_days if {
	inp := {"google": {"kms": {"keyrings": [{"keys": [{"rotationperiodseconds": {"value": 2592000}}]}]}}} # 30 days

	check.deny with input as inp == set()
}
