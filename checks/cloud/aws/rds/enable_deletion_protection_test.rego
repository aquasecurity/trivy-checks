package builtin.aws.rds.aws0177

import rego.v1

test_detects_when_disabled if {
	r := deny with input as {"aws": {"rds": {"instances": [{"deletionprotection": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled if {
	r := deny with input as {"aws": {"rds": {"instances": [{"deletionprotection": {"value": true}}]}}}
	count(r) == 0
}
