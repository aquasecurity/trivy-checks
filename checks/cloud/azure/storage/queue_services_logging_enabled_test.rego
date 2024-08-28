package builtin.azure.storage.azure0009_test

import rego.v1

import data.builtin.azure.storage.azure0009 as check
import data.lib.test

test_deny_logging_disabled if {
	inp := {"azure": {"storage": {"accounts": [{
		"queues": [{"name": {"value": "test"}}],
		"queueproperties": {"enablelogging": {"value": false}},
	}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_logging_enabled if {
	inp := {"azure": {"storage": {"accounts": [{
		"queues": [{"name": {"value": "test"}}],
		"queueproperties": {"enablelogging": {"value": true}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_logging_disabled_but_queues_are_empty if {
	inp := {"azure": {"storage": {"accounts": [{
		"queues": [],
		"queueproperties": {"enablelogging": {"value": false}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}
