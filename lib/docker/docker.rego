# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: dockerfile
package lib.docker

import rego.v1

from contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "from"
}

add contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "add"
}

run contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "run"
}

copy contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "copy"
}

stage_copies[stage] := copies if {
	stage := input.Stages[_]
	copies := [copy | copy := stage.Commands[_]; copy.Cmd == "copy"]
}

entrypoint contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "entrypoint"
}

stage_entrypoints[stage] := entrypoints if {
	stage := input.Stages[_]
	entrypoints := [entrypoint | entrypoint := stage.Commands[_]; entrypoint.Cmd == "entrypoint"]
}

stage_cmd[stage] := cmds if {
	stage := input.Stages[_]
	cmds := [cmd | cmd := stage.Commands[_]; cmd.Cmd == "cmd"]
}

stage_healthcheck[stage] := hlthchecks if {
	stage := input.Stages[_]
	hlthchecks := [hlthcheck | hlthcheck := stage.Commands[_]; hlthcheck.Cmd == "healthcheck"]
}

stage_user[stage] := users if {
	stage := input.Stages[_]
	users := [cmd | cmd := stage.Commands[_]; cmd.Cmd == "user"]
}

expose contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "expose"
}

user contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "user"
}

workdir contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "workdir"
}

healthcheck contains instruction if {
	instruction := input.Stages[_].Commands[_]
	instruction.Cmd == "healthcheck"
}

split_cmd(s) := cmds if {
	cmd_parts := regex.split(`\s*&&\s*`, s)
	cmds := [split(cmd, " ") | cmd := cmd_parts[_]]
}

command_indexes(cmds, cmds_to_check, package_manager) := cmd_indexes if {
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
