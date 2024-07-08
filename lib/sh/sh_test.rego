package lib.sh_test

test_parse_commands_with_ampersands {
	cmds := sh.parse_commands("apt update && apt install curl")
	count(cmds) == 2
	cmds[0] == ["apt", "update"]
	cmds[1] == ["apt", "install", "curl"]
}

test_parse_commands_empty_input {
	cmds := sh.parse_commands("")
	count(cmds) == 0
}

test_parse_commands_with_semicolon {
	cmds := sh.parse_commands("apt update;apt install curl")
	count(cmds) == 2
	cmds[0] == ["apt", "update"]
	cmds[1] == ["apt", "install", "curl"]
}

test_parse_commands_mixed {
	cmds := sh.parse_commands("apt update; apt install curl && apt install git")
	count(cmds) == 3
	cmds[0] == ["apt", "update"]
	cmds[1] == ["apt", "install", "curl"]
	cmds[2] == ["apt", "install", "git"]
}
