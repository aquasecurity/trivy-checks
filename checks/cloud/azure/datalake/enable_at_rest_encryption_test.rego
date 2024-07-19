package builtin.azure.datalake.azure0036_test

import rego.v1

import data.builtin.azure.datalake.azure0036 as check
import data.lib.test

test_deny_unencrypted_data_lake_store if {
	res := check.deny with input as build_input(false)
	count(res) == 1
}

test_allow_encrypted_data_lake_store if {
	res := check.deny with input as build_input(true)
	count(res) == 0
}

build_input(enable) := {"azure": {"datalake": {"stores": [{"enableencryption": {"value": enable}}]}}}
