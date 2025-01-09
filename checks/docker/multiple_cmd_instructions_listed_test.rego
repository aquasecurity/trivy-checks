package builtin.dockerfile.DS016

import rego.v1

test_denied if {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.7.3", "Commands": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./apps"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		]},
	]}

	count(r) == 1
	r[_].msg == "There are 2 duplicate CMD instructions"
}

test_allowed if {
	r := deny with input as {"Stages": [
		{"Name": "golang:1.7.3", "Commands": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		]},
		{"Name": "alpine:latest", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		]},
	]}

	count(r) == 0
}
