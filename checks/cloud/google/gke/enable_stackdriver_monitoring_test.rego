package builtin.google.gke.google0052_test

import rego.v1

import data.builtin.google.gke.google0052 as check
import data.lib.test

test_deny_stackdriver_monitoring_disabled if {
	inp := {"google": {"gke": {"clusters": [{"monitoringservice": {"value": ""}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_stackdriver_monitoring_enabled if {
	inp := {"google": {"gke": {"clusters": [{"monitoringservice": {"value": "monitoring.googleapis.com/kubernetes"}}]}}}

	res := check.deny with input as inp
	res == set()
}
