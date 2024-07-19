package builtin.azure.securitycenter.azure0044_test

import rego.v1

import data.builtin.azure.securitycenter.azure0044 as check
import data.lib.test

test_deny_security_center_alert_notifications_disabled if {
	res := check.deny with input as build_input(false)
	count(res) == 1
}

test_allow_security_center_alert_notifications_enabled if {
	res := check.deny with input as build_input(true)
	count(res) == 0
}

build_input(enabled) := {"azure": {"securitycenter": {"contacts": [{"enablealertnotifications": {"value": enabled}}]}}}
