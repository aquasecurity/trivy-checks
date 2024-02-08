package builtin.dockerfile.DS030

test_basic_denied {
	r := deny with input as {"Stages": [{"Name": "alpine:3.5", "Commands": [
		{"Cmd": "from", "Value": ["alpine:3.5"]},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "workdir",
			"Value": ["/proc/self/fd/1"],
		},
	]}]}

	count(r) == 1
	r[_].msg == "WORKDIR path '/proc/self/fd/1' should not mount system directories"
}

test_no_work_dir_allowed {
	r := deny with input as {"Stages": [{"Name": "alpine:3.3", "Commands": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.3"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --no-cache add nginx"],
		},
	]}]}

	count(r) == 0
}

test_non_sys_work_dir_allowed {
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
			"Cmd": "workdir",
			"Value": ["/path/to/workdir"],
		},
	]}]}

	count(r) == 0
}

test_non_sys_work_dir_similar_to_fs_allowed {
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
			"Cmd": "workdir",
			"Value": ["/development"],
		},
	]}]}

	count(r) == 0
}

test_absolute_work_dir_with_quotes_allowed {
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
			"Cmd": "workdir",
			"Value": ["\"/path/to/workdir\""],
		},
	]}]}

	count(r) == 0
}

test_absolute_work_dir_with_quotes_with_sys_dir_denied {
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
			"Cmd": "workdir",
			"Value": ["\"/proc/self/fd/1\""],
		},
	]}]}

	count(r) == 1
	r[_].msg == "WORKDIR path '\"/proc/self/fd/1\"' should not mount system directories"
}
