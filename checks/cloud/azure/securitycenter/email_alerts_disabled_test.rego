package builtin.azure.securitycenter.azure0063_test

import rego.v1

import data.builtin.azure.securitycenter.azure0063 as check

test_deny_alert_notifications_disabled if {
	res := check.deny with input as build_input_notifications(false, true)
	count(res) == 1
}

test_deny_alerts_to_admins_disabled if {
	res := check.deny with input as build_input_notifications(true, false)
	count(res) == 1
}

test_deny_both_alerts_disabled if {
	res := check.deny with input as build_input_notifications(false, false)
	count(res) == 2
}

test_deny_missing_alert_notifications if {
	res := check.deny with input as build_input_no_notifications
	count(res) == 2
}

test_allow_both_alerts_enabled if {
	res := check.deny with input as build_input_notifications(true, true)
	count(res) == 0
}

build_input_notifications(alert_notifications, alerts_to_admins) := {"azure": {"securitycenter": {"contacts": [{
	"enablealertnotifications": {"value": alert_notifications},
	"enablealertstoadmins": {"value": alerts_to_admins},
}]}}}

build_input_no_notifications := {"azure": {"securitycenter": {"contacts": [{}]}}}
