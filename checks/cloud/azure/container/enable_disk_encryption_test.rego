package builtin.azure.container.azure0067_test

import rego.v1

import data.builtin.azure.container.azure0067 as check

test_deny_disk_encryption_not_configured if {
	inp := {"azure": {"container": {"kubernetesclusters": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_disk_encryption_empty if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"diskencryptionsetid": {"value": ""}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_disk_encryption_configured if {
	inp := {"azure": {"container": {"kubernetesclusters": [{"diskencryptionsetid": {"value": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/example/providers/Microsoft.Compute/diskEncryptionSets/example"}}]}}}
	res := check.deny with input as inp
	res == set()
}
