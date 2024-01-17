# METADATA
# title: "COPY with more than two arguments not ending with slash"
# description: "When a COPY command has more than two arguments, the last one should end with a slash."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/engine/reference/builder/#copy
# custom:
#   id: DS011
#   avd_id: AVD-DS-0011
#   severity: CRITICAL
#   short_code: use-slash-for-copy-args
#   recommended_action: "Add slash to last COPY argument"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS011

import data.lib.docker

get_copy_arg[output] {
	copy := docker.copy[_]

	cnt := count(copy.Value)
	cnt > 2

	not is_command_with_hash(copy.Value, "file:")
	not is_command_with_hash(copy.Value, "multi:")

	arg := copy.Value[cnt - 1]
	not endswith(arg, "/")
	output := {
		"arg": arg,
		"cmd": copy,
	}
}

is_command_with_hash(cmd, prefix) {
	count(cmd) == 3
	startswith(cmd[0], prefix)
	cmd[1] == "in"
}

deny[res] {
	output := get_copy_arg[_]
	msg := sprintf("Slash is expected at the end of COPY command argument '%s'", [output.arg])
	res := result.new(msg, output.cmd)
}
