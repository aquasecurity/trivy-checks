package builtin.dockerfile.DS010

import rego.v1

test_basic_denied if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "run",
			"Value": ["sudo pip install --upgrade pip"],
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
	r[_].msg == "Using 'sudo' in Dockerfile should be avoided"
}

test_chaining_denied if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["RUN apk add bash && sudo pip install --upgrade pip"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "Using 'sudo' in Dockerfile should be avoided"
}

test_multi_vuls_denied if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["RUN sudo pip install --upgrade pip"],
		},
		{
			"Cmd": "run",
			"Value": ["RUN apk add bash && sudo pip install --upgrade pip"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "Using 'sudo' in Dockerfile should be avoided"
}

test_basic_allowed if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.3", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install sudo"],
		},
		{
			"Cmd": "cmd",
			"Value": ["python", "/usr/src/app/app.py"],
		},
	]}]}

	count(r) == 0
}
