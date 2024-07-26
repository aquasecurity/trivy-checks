package builtin.nifcloud.network.nifcloud0020_test

import rego.v1

import data.builtin.nifcloud.network.nifcloud0020 as check
import data.lib.test

test_allow_lb_using_tls_v12 if {
	inp := {"nifcloud": {"network": {"loadbalancers": [{"listeners": [{
		"protocol": {"value": "HTTPS"},
		"tlspolicy": {"value": "Standard Ciphers D ver1"},
	}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_lb_using_ICMP if {
	inp := {"nifcloud": {"network": {"loadbalancers": [{"listeners": [{
		"protocol": {"value": "ICMP"},
		"tlspolicy": {"value": ""},
	}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_lb_using_tls_v1 if {
	inp := {"nifcloud": {"network": {"loadbalancers": [{"listeners": [{
		"protocol": {"value": "HTTPS"},
		"tlspolicy": {"value": "Standard Ciphers A ver1"},
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
