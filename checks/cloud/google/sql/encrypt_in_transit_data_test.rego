package builtin.google.sql.google0015_test

import rego.v1

import data.builtin.google.sql.google0015 as check

test_allow_tls_required if {
	inp := build_input({"requiretls": {"value": true}})
	res := check.deny with input as inp
	res == set()
}

test_deny_tls_not_required if {
	inp := build_input({"requiretls": {"value": false}})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ssl_mode_require_ssl if {
	inp := build_input({"requiretls": {"value": false}, "sslmode": {"value": check.ssl_trusted_cert_required}})

	res := check.deny with input as inp
	res == set()
}

test_allow_ssl_mode_require_ssl_2 if {
	inp := build_input({"requiretls": {"value": false}, "sslmode": {"value": check.ssl_encrypted_only}})

	res := check.deny with input as inp
	res == set()
}

build_input(ipconfig) := {"google": {"sql": {"instances": [{"settings": {"ipconfiguration": ipconfig}}]}}}
