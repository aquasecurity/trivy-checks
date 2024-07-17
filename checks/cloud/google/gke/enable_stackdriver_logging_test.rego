package builtin.google.gke.google0060_test

import rego.v1

import data.builtin.google.gke.google0060 as check
import data.lib.test

test_deny_stackdriver_logging_disabled if {
	inp := {"google": {"gke": {"clusters": [{"loggingservice": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_stackdriver_logging_enabled if {
	inp := {"google": {"gke": {"clusters": [{"loggingservice": {"value": "logging.googleapis.com/kubernetes"}}]}}}

	res := check.deny with input as inp
	res == set()
}
