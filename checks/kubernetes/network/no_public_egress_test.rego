package builtin.kube.network.kube0002_test

import rego.v1

import data.builtin.kube.network.kube0002 as check
import data.lib.test

test_allow_private_source if {
	inp := {"kubernetes": {"networkpolicies": [{"spec": {"egress": {"destinationcidrs": [{"value": "10.0.0.0/16"}]}}}]}}
	test.assert_empty(check.deny) with input as inp
}

test_deny_public_source if {
	inp := {"kubernetes": {"networkpolicies": [{"spec": {"egress": {"destinationcidrs": [{"value": "0.0.0.0/0"}]}}}]}}
	test.assert_count(check.deny, 1) with input as inp
}
