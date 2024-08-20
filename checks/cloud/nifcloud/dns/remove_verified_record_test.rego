package builtin.nifcloud.dns.nifcloud0007_test

import rego.v1

import data.builtin.nifcloud.dns.nifcloud0007 as check
import data.lib.test

test_allow_txt_record if {
	inp := build_input({
		"type": {"value": "TXT"},
		"record": {"value": "test"},
	})

	res := check.deny with input as inp
	res == set()
}

test_deny_verified_txt_record if {
	inp := build_input({
		"type": {"value": "TXT"},
		"record": {"value": "nifty-dns-verify=test"},
	})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_verified_not_txt_record if {
	inp := build_input({
		"type": {"value": "A"},
		"record": {"value": "nifty-dns-verify=test"},
	})

	res := check.deny with input as inp
	res == set()
}

build_input(record) := {"nifcloud": {"dns": {"records": [record]}}}
