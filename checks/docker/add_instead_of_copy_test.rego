package builtin.dockerfile.DS005

test_mixed_commands_denied {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [
			{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]},
			{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]},
		],
	}]}

	count(r) == 1
	r[_].msg == "Consider using 'COPY /target/app.jar app.jar' command instead of 'ADD /target/app.jar app.jar'"
}

test_add_command_denied {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{
			"Cmd": "add",
			"Value": ["/target/app.jar", "app.jar"],
		}],
	}]}

	count(r) == 1
	r[_].msg == "Consider using 'COPY /target/app.jar app.jar' command instead of 'ADD /target/app.jar app.jar'"
}

test_run_allowed {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{"Cmd": "run", "Value": ["tar -xjf /temp/package.file.tar.gz"]}],
	}]}

	count(r) == 0
}

test_copy_allowed {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{"Cmd": "copy", "Value": ["test.txt", "test2.txt"]}],
	}]}

	count(r) == 0
}

test_add_file_colon_in_allowed {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{"Cmd": "add", "Value": ["file:8b8864b3e02a33a579dc216fd51b28a6047bc8eeaa03045b258980fe0cf7fcb3", "in", "/xyz"]}],
	}]}

	count(r) == 0
}

test_add_multi_colon_in_allowed {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{"Cmd": "add", "Value": ["multi:8b8864b3e02a33a579dc216fd51b28a6047bc8eeaa03045b258980fe0cf7fcb3", "in", "/xyz"]}],
	}]}

	count(r) == 0
}

test_add_tar_allowed {
	r := deny with input as {"Stages": [{
		"Name": "alpine:3.13",
		"Commands": [{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.tar.gz"]}],
	}]}

	count(r) == 0
}
