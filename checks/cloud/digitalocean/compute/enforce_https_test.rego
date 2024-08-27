package builtin.digitalocean.compute.digitalocean0002_test

import rego.v1

import data.builtin.digitalocean.compute.digitalocean0002 as check
import data.lib.test

test_deny_rule_using_http if {
	inp := {"digitalocean": {"compute": {"loadbalancers": [{"forwardingrules": [{"entryprotocol": {"value": "http"}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_rule_using_https if {
	inp := {"digitalocean": {"compute": {"loadbalancers": [{"forwardingrules": [{"entryprotocol": {"value": "https"}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_rule_using_http_but_redirect_to_https if {
	inp := {"digitalocean": {"compute": {"loadbalancers": [{
		"redirecthttptohttps": {"value": true},
		"forwardingrules": [{"entryprotocol": {"value": "http"}}],
	}]}}}

	test.assert_empty(check.deny) with input as inp
}
