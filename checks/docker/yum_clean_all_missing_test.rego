package builtin.dockerfile.DS015

import rego.v1

test_basic_denied if {
	r := deny with input as {"Stages": [
		{"Name": "alpine:3.5", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "run",
				"Value": ["yum install vim"],
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
		{"Name": "alpine:3.4", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.4"],
			},
			{
				"Cmd": "run",
				"Value": ["yum -y install vim && yum clean all"],
			},
		]},
	]}

	count(r) == 1
	r[_].msg == "'yum clean all' is missed: yum install vim"
}

test_wrong_order_of_commands_denied if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum clean all && yum -y install"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'yum clean all' is missed: yum clean all && yum -y install"
}

test_multiple_install_denied if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum -y install bash && yum clean all && yum -y install zsh"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'yum clean all' is missed: yum -y install bash && yum clean all && yum -y install zsh"
}

test_multiple_install_allowed if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum -y install bash && yum clean all && yum -y install zsh && yum clean all"],
		},
	]}]}

	count(r) == 0
}

test_basic_allowed if {
	r := deny with input as {"Stages": [
		{"Name": "alpine:3.5", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "run",
				"Value": ["yum install && yum clean all"],
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
		{"Name": "alpine:3.4", "Commands": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.4"],
			},
			{
				"Cmd": "run",
				"Value": ["yum -y install && yum clean all"],
			},
		]},
	]}

	count(r) == 0
}

test_allow_clean_with_flags if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": [`if [ "$TBB" == "default" ]; then  yum -y install tbb tbb-devel && yum clean -y all ; fi`],
		},
	]}]}

	count(r) == 0
}

test_denied_clean_not_all if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum -y install bash && yum clean metadata"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "'yum clean all' is missed: yum -y install bash && yum clean metadata"
}

test_allow_only_clean if {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum clean all"],
		},
	]}]}

	count(r) == 0
}
