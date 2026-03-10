# METADATA
# custom:
#   library: true
#   input:
#     selector:
#     - type: dockerfile
package lib.docker

import rego.v1

from := instructions("from")

add := instructions("add")

run := instructions("run")

copy := instructions("copy")

entrypoint := instructions("entrypoint")

expose := instructions("expose")

user := instructions("user")

workdir := instructions("workdir")

healthcheck := instructions("healthcheck")

stage_copies := stage_instructions("copy")

stage_entrypoints := stage_instructions("entrypoint")

stage_run := stage_instructions("run")

stage_cmd := stage_instructions("cmd")

stage_healthcheck := stage_instructions("healthcheck")

stage_user := stage_instructions("user")

instructions(typ) := [inst |
	some stage in input.Stages
	some inst in stage.Commands
	inst.Cmd == typ
]

stage_instructions(typ) := {stage: instructions |
	some stage in input.Stages
	instructions := [inst |
		some inst in stage.Commands
		inst.Cmd == typ
	]
}

split_cmd(s) := sh.parse_commands(s)

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
