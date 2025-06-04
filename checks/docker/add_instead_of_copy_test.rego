package builtin.dockerfile.DS005_test

import rego.v1

import data.builtin.dockerfile.DS005 as check

test_add_command[name] if {
	some name, tc in {
		"mixed ADD commands and only one invalid": {
			"cmds": [
				{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]},
				{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]},
			],
			"expected": 1,
		},
		"single invalid ADD command": {
			"cmds": [{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]}],
			"expected": 1,
		},
		"RUN command allowed": {
			"cmds": [{"Cmd": "run", "Value": ["tar -xjf /temp/package.file.tar.gz"]}],
			"expected": 0,
		},
		"COPY command allowed": {
			"cmds": [{"Cmd": "copy", "Value": ["test.txt", "test2.txt"]}],
			"expected": 0,
		},
		"ADD with file:... in ... allowed": {
			"cmds": [{"Cmd": "add", "Value": ["file:8b8864b3e02a33a579dc216fd51b28a6047bc8eeaa03045b258980fe0cf7fcb3", "in", "/xyz"]}],
			"expected": 0,
		},
		"ADD with file:... without 'in' allowed": {
			"cmds": [{"Cmd": "add", "Value": ["file:8b8864b3e02a33a579dc216fd51b28a6047bc8eeaa03045b258980fe0cf7fcb3", "/xyz"]}],
			"expected": 0,
		},
		"ADD with multi:... in ... allowed": {
			"cmds": [{"Cmd": "add", "Value": ["multi:8b8864b3e02a33a579dc216fd51b28a6047bc8eeaa03045b258980fe0cf7fcb3", "in", "/xyz"]}],
			"expected": 0,
		},
		"ADD with .tar.gz allowed": {
			"cmds": [{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.tar.gz"]}],
			"expected": 0,
		},
		"ADD with http URL allowed": {
			"cmds": [{"Cmd": "add", "Value": ["http://example.com/foo.txt", "bar.txt"]}],
			"expected": 0,
		},
		"ADD with https URL allowed": {
			"cmds": [{"Cmd": "add", "Value": ["https://example.com/foo.txt", "bar.txt"]}],
			"expected": 0,
		},
		"ADD with git@ URL allowed": {
			"cmds": [{"Cmd": "add", "Value": ["git@github.com:user/repo.git", "/usr/src/things/"]}],
			"expected": 0,
		},
	}

	r := check.deny with input as {"Stages": [{"Name": "alpine:3.13", "Commands": tc.cmds}]}
	count(r) == tc.expected
}
