# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: dockerfile
package lib.docker

from[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "from"
}

add[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "add"
}

run[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "run"
}

copy[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "copy"
}

stage_copies[stage] = copies {
	stage := input.Stages[_]
	copies := [copy | copy := stage.Commands[_]; copy.Cmd == "copy"]
}

entrypoint[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "entrypoint"
}

stage_entrypoints[stage] = entrypoints {
	stage := input.Stages[_]
	entrypoints := [entrypoint | entrypoint := stage.Commands[_]; entrypoint.Cmd == "entrypoint"]
}

stage_cmd[stage] = cmds {
	stage := input.Stages[_]
	cmds := [cmd | cmd := stage.Commands[_]; cmd.Cmd == "cmd"]
}

stage_healthcheck[stage] = hlthchecks {
	stage := input.Stages[_]
	hlthchecks := [hlthcheck | hlthcheck := stage.Commands[_]; hlthcheck.Cmd == "healthcheck"]
}

stage_user[stage] = users {
	stage := input.Stages[_]
	users := [cmd | cmd := stage.Commands[_]; cmd.Cmd == "user"]
}

expose[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "expose"
}

user[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "user"
}

workdir[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "workdir"
}

healthcheck[instruction] {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "healthcheck"
}

split_cmd(s) := cmds {
	cmd_parts := regex.split(`\s*&&\s*`, s)
	cmds := [split(cmd, " ") | cmd := cmd_parts[_]]
}

command_indexes(cmds, cmds_to_check, package_manager) = cmd_indexes {
	cmd_indexes = [idx |
		cmd_parts := cmds[idx]
		some i, j
		i != j
		cmd_parts[i] == package_manager[_]
		cmd_parts[j] == cmds_to_check[_]
		i < j
	]
	count(cmd_indexes) != 0
}
