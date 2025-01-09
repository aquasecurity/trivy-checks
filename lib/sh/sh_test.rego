package lib.sh_test

import rego.v1

test_parse_commands_with_ampersands if {
	cmds := sh.parse_commands("apt update && apt install curl")
	count(cmds) == 2
	cmds[0] == ["apt", "update"]
	cmds[1] == ["apt", "install", "curl"]
}

test_parse_commands_empty_input if {
	cmds := sh.parse_commands("")
	count(cmds) == 0
}

test_parse_commands_with_semicolon if {
	cmds := sh.parse_commands("apt update;apt install curl")
	count(cmds) == 2
	cmds[0] == ["apt", "update"]
	cmds[1] == ["apt", "install", "curl"]
}

test_parse_commands_mixed if {
	cmds := sh.parse_commands("apt update; apt install curl && apt install git")
	count(cmds) == 3
	cmds[0] == ["apt", "update"]
	cmds[1] == ["apt", "install", "curl"]
	cmds[2] == ["apt", "install", "git"]
}
