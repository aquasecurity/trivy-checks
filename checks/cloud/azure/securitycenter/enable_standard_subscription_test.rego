package builtin.azure.securitycenter.azure0045_test

import rego.v1

import data.builtin.azure.securitycenter.azure0045 as check
import data.lib.test

test_deny_subscription_use_free_tier if {
	inp := {"azure": {"securitycenter": {"subscriptions": [{"tier": {"value": check.free_tier}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_subscription_use_standard_tier if {
	inp := {"azure": {"securitycenter": {"subscriptions": [{"tier": {"value": "Standard"}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
