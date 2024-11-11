package builtin.aws.rds.aws0343

test_deny_deletion_protection_disabled {
	r := deny with input as {"aws": {"rds": {"clusters": [{"deletionprotection": {"value": false}}]}}}
	count(r) == 1
}

test_allow_deletion_protection_enabled {
	r := deny with input as {"aws": {"rds": {"clusters": [{"deletionprotection": {"value": true}}]}}}
	count(r) == 0
}

# If there is no cluster for database instances, they are added to an empty cluster.
test_allow_deletion_protection_disabled_but_instances_orphaned {
	r := deny with input as {"aws": {"rds": {"clusters": [{"deletionprotection": {"__defsec_metadata": {"managed": false}, "value": false}}]}}}
	count(r) == 0
}
