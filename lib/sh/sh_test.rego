package lib.sh_test

import rego.v1

test_parse_commands_cases[name] if {
	some name, tc in {
		"ampersands": {
			"input": "apt update && apt install curl",
			"expected": [["apt", "update"], ["apt", "install", "curl"]],
		},
		"semicolon": {
			"input": "apt update;apt install curl",
			"expected": [["apt", "update"], ["apt", "install", "curl"]],
		},
		"mixed": {
			"input": "apt update; apt install curl && apt install git",
			"expected": [["apt", "update"], ["apt", "install", "curl"], ["apt", "install", "git"]],
		},
	}

	cmds := sh.parse_commands(tc.input)
	cmds == tc.expected
}

test_parse_commands_empty if {
	cmds := sh.parse_commands("")
	count(cmds) == 0
}

test_has_pipes_true_cases[name] if {
	some name, tc in {
		"simple pipe": {"input": "wget -O - https://some.site | wc -l"},
		"pipe with pipefail": {"input": "set -o pipefail && wget -O - https://some.site | wc -l"},
	}
	sh.has_pipes(tc.input)
}

test_has_pipes_false_cases[name] if {
	some name, tc in {
		"ampersands": {"input": "apt update && apt install curl"},
		"semicolon": {"input": "apt update; apt install curl"},
		"or": {"input": "apt update || apt install curl"},
		"pipe in string": {"input": `echo "foo|bar"`},
		"empty": {"input": ""},
	}
	not sh.has_pipes(tc.input)
}
