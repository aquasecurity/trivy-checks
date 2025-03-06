package builtin.aws.ami.aws0344

import rego.v1

test_denied_missing_owners if {
    r := deny with input as {"aws": {"ami": {}}}
    count(r) == 1
    r[_].msg == "AWS AMI data source should specify owners to ensure AMIs come from trusted sources"
}

test_denied_empty_owners if {
    r := deny with input as {"aws": {"ami": {"owners": [""]}}}
    count(r) == 1
    r[_].msg == "AWS AMI data source should specify owners to ensure AMIs come from trusted sources"
}

test_allowed_valid_owners if {
    r := deny with input as {"aws": {"ami": {"owners": ["self"]}}}
    count(r) == 0
}

test_allowed_valid_multiple_owners if {
    r := deny with input as {"aws": {"ami": {"owners": ["amazon", "self"]}}}
    count(r) == 0
}