package builtin.dockerfile.DS024

import rego.v1

test_denied if {
	r := deny with input as {"Stages": [{"Name": "debian", "Commands": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get dist-upgrade"],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"python",
				"/usr/src/app/app.py",
			],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'apt-get dist-upgrade' should not be used in Dockerfile"
}

test_shortflag_denied if {
	r := deny with input as {"Stages": [{"Name": "debian", "Commands": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get -q dist-upgrade"],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"python",
				"/usr/src/app/app.py",
			],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'apt-get dist-upgrade' should not be used in Dockerfile"
}

test_longflag_denied if {
	r := deny with input as {"Stages": [{"Name": "debian", "Commands": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get --quiet dist-upgrade"],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"python",
				"/usr/src/app/app.py",
			],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'apt-get dist-upgrade' should not be used in Dockerfile"
}

test_allowed if {
	r := deny with input as {"Stages": [{"Name": "debian", "Commands": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get upgrade"],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"python",
				"/usr/src/app/app.py",
			],
		},
	]}]}

	count(r) == 0
}
