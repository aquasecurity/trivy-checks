package builtin.azure.datafactory.azure0035_test

import rego.v1

import data.builtin.azure.datafactory.azure0035 as check
import data.lib.test

test_deny_datafactory_public_access_enabled if {
	res := check.deny with input as build_input(true)
	count(res) == 1
}

test_allow_datafactory_public_access_disabled if {
	res := check.deny with input as build_input(false)
	count(res) == 0
}

build_input(enabled) := {"azure": {"datafactory": {"datafactories": [{"enablepublicnetwork": {"value": enabled}}]}}}
