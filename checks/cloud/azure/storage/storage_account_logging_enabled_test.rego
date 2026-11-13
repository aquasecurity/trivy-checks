package builtin.azure.storage.azure0057_test

import rego.v1

import data.builtin.azure.storage.azure0057 as check
import data.lib.test

test_deny_logging_disabled if {
	inp := {"azure": {"storage": {"accounts": [{
		"diagnosticloggingenabled": {"value": false},
		"queueproperties": {"enablelogging": {"value": false}},
	}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_logging_not_configured if {
	inp := {"azure": {"storage": {"accounts": [{"diagnosticloggingenabled": {"value": false}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_queue_logging_enabled if {
	inp := {"azure": {"storage": {"accounts": [{
		"diagnosticloggingenabled": {"value": false},
		"queueproperties": {"enablelogging": {"value": true}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_diagnostic_logging_enabled if {
	inp := {"azure": {"storage": {"accounts": [{"diagnosticloggingenabled": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_diagnostic_logging_enabled_with_legacy_logging_disabled if {
	inp := {"azure": {"storage": {"accounts": [{
		"diagnosticloggingenabled": {"value": true},
		"queueproperties": {"enablelogging": {"value": false}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}
