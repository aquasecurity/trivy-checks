package builtin.dockerfile.DS022

import rego.v1

test_denied if {
	r := deny with input as {"Stages": [{"Name": "fedora:27", "Commands": [
		{
			"Cmd": "from",
			"Value": ["fedora:27"],
		},
		{
			"Cmd": "maintainer",
			"Value": ["admin@example.com"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "MAINTAINER should not be used: 'MAINTAINER admin@example.com'"
}

test_allowed if {
	r := deny with input as {"Stages": [{"Name": "fedora:27", "Commands": [{
		"Cmd": "from",
		"Value": ["fedora:27"],
	}]}]}

	count(r) == 0
}
