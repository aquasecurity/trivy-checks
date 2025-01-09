package builtin.dockerfile.DS008

import rego.v1

test_denied if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.3", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.3"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --no-cache add nginx"],
		},
		{
			"Cmd": "expose",
			"Value": [
				"65536/tcp",
				"80",
				"443",
				"22",
			],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"nginx",
				"-g",
				"daemon off;",
			],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'EXPOSE' contains port which is out of range [0, 65535]: 65536"
}

test_allowed if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.3", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.3"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --no-cache add nginx"],
		},
		{
			"Cmd": "expose",
			"Value": [
				"65530/tcp",
				"80",
				"443",
				"22",
			],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"nginx",
				"-g",
				"daemon off;",
			],
		},
	]}]}

	count(r) == 0
}
