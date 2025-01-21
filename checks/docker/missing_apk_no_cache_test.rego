package builtin.dockerfile.DS025

import rego.v1

test_basic_denied if {
	r := deny with input as {"Stages": [
		{"Name": "alpine:3.17", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.17"],
			},
			{
				"Cmd": "run",
				"Value": ["apk add python3"],
			},
			{
				"Cmd": "run",
				"Value": ["pip install --no-cache-dir -r /usr/src/app/requirements.txt"],
			},
			{
				"Cmd": "cmd",
				"Value": [
					"python",
					"/usr/src/app/app.py",
				],
			},
		]},
		{"Name": "alpine:3.15", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.4"],
			},
			{
				"Cmd": "run",
				"Value": [""],
			},
		]},
	]}

	count(r) == 1
	r[_].msg == "'--no-cache' is missed: apk add python3"
}

test_deny_run_is_array if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.17", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.17"],
		},
		{
			"Cmd": "run",
			"Value": ["apk", "add", "python3"],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --no-cache-dir -r /usr/src/app/requirements.txt"],
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
	r[_].msg == "'--no-cache' is missed: apk add python3"
}

test_wrong_flag_name_denied if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["apk add --no-cacher bash"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'--no-cache' is missed: apk add --no-cacher bash"
}

test_last_no_cache_allowed if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.14"],
		},
		{
			"Cmd": "run",
			"Value": ["apk add bash --no-cache"],
		},
	]}]}

	count(r) == 0
}

test_basic_allowed if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.17", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.17"],
		},
		{
			"Cmd": "run",
			"Value": ["apk add --no-cache python3"],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --no-cache-dir -r /usr/src/app/requirements.txt"],
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

test_deny_no_cache_flag_with_other_command if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.17", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.17"],
		},
		{
			"Cmd": "run",
			"Value": ["apk upgrade --no-cache && apk add python3"],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --no-cache-dir -r /usr/src/app/requirements.txt"],
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
	r[_].msg == "'--no-cache' is missed: apk upgrade --no-cache && apk add python3"
}
