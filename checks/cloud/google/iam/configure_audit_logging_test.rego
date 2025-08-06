package builtin.google.iam.google0079_test

import rego.v1

import data.builtin.google.iam.google0079 as check

test_deny_project_without_audit_config if {
	inp := {"google": {"iam": {"projects": [{"auditconfigs": []}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_audit_config_wrong_service_scope if {
	inp := {"google": {"iam": {"projects": [{"auditconfigs": [{"service": {"value": "cloudresourcemanager.googleapis.com"}, "auditlogconfigs": [
		{"logtype": {"value": "ADMIN_READ"}},
		{"logtype": {"value": "DATA_READ"}},
		{"logtype": {"value": "DATA_WRITE"}},
	]}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_audit_config_missing_log_types if {
	inp := {"google": {"iam": {"projects": [{"auditconfigs": [{"service": {"value": "allServices"}, "auditlogconfigs": [{"logtype": {"value": "ADMIN_READ"}}]}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_proper_audit_config if {
	inp := {"google": {"iam": {"projects": [{"auditconfigs": [{"service": {"value": "allServices"}, "auditlogconfigs": [
		{"logtype": {"value": "ADMIN_READ"}},
		{"logtype": {"value": "DATA_READ"}},
		{"logtype": {"value": "DATA_WRITE"}},
	]}]}]}}}

	res := check.deny with input as inp
	res == set()
}
