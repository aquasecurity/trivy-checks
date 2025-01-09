package builtin.aws.s3.aws0320

import rego.v1

test_detects_when_has_not_dns_compliant_name if {
	r := deny with input as {"aws": {"s3": {"buckets": [{"name": {"value": "sana.test"}}]}}}
	count(r) == 1
}

test_when_has_dns_compliant_name if {
	r := deny with input as {"aws": {"s3": {"buckets": [{"name": {"value": "sana-test"}}]}}}
	count(r) == 0
}
