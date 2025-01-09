package builtin.aws.rds.aws0176

import rego.v1

test_detects_when_disabled if {
	r := deny with input as {"aws": {"rds": {"instances": [{
		"engine": {"value": "postgres"},
		"iamauthenabled": {"value": false},
	}]}}}
	count(r) == 1
}

test_when_enabled if {
	r := deny with input as {"aws": {"rds": {"instances": [{
		"engine": {"value": "postgres"},
		"iamauthenabled": {"value": true},
	}]}}}
	count(r) == 0
}

test_when_not_applicable if {
	r := deny with input as {"aws": {"rds": {"instances": [{
		"engine": {"value": "aurora"},
		"iamauthenabled": {"value": false},
	}]}}}
	count(r) == 0
}
