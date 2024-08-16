package lib.cidr_test

import rego.v1

import data.lib.test

uint64max = 18446744073709551615

test_count_addresses if {
	cidr.count_addresses("*") == uint64max
	cidr.count_addresses("1.2.3.4/32") == 1
}

test_is_public if {
	cidr.is_public("*") == true
	cidr.is_public("0.0.0.0/0") == true
	cidr.is_public("10.0.0.0/16") == false
}
