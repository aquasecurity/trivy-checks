package builtin.aws.rds.aws0180

import rego.v1

test_detects_when_disabled if {
	r := deny with input as {"aws": {"rds": {"instances": [{"publicaccess": {"value": false}}]}}}
	count(r) == 0
}

test_when_enabled if {
	r := deny with input as {"aws": {"rds": {"instances": [{"publicaccess": {"value": true}}]}}}
	count(r) == 1
}

test_when_cluster_disabled if {
	r := deny with input as {"aws": {"rds": {"clusters": [{"instances": [{"instance": {"publicaccess": {"value": false}}}]}]}}}
	count(r) == 0
}

test_when_cluster_enabled if {
	r := deny with input as {"aws": {"rds": {"clusters": [{"instances": [{"instance": {"publicaccess": {"value": true}}}]}]}}}
	count(r) == 1
}
