# METADATA
# title: "RUN with pipe without pipefail"
# description: |
#  "RUN instruction with a pipe should use 'set -o pipefail' to ensure that errors in any part of the pipe are caught.
#  If you are using a shell that does not support pipefail, consider switching to /bin/bash or /bin/ash."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/build/building/best-practices/#using-pipes
# custom:
#   id: DS-0032
#   long_id: docker-pipefail
#   aliases:
#     - docker-pipefail
#   severity: LOW
#   minimum_trivy_version: 1.0.0
#   recommended_action: "Add 'set -o pipefail' before the pipe in the RUN instruction, or switch to a shell that supports pipefail via the SHELL instruction"
#   input:
#     selector:
#     - type: dockerfile
#   examples: checks/docker/run_pipefail.yaml
package builtin.dockerfile.DS032

import rego.v1

non_posix_shells := {"pwsh", "powershell", "cmd"}

pipefail_supported_shells := {"/bin/bash", "/bin/zsh", "/bin/ash", "bash", "zsh", "ash"}

shell_has_pipefail(values) if {
	values[0] in pipefail_supported_shells
	some i
	values[i] == "-o"
	values[i + 1] == "pipefail"
}

shell_has_pipefail(values) if {
	values[0] in pipefail_supported_shells
	some i
	val := values[i]
	startswith(val, "-")
	not startswith(val, "--")
	count(val) > 2
	contains(val, "o")
	values[i + 1] == "pipefail"
}

active_shell_before(stage, run_index) := cmd if {
	i := max({i |
		some i, cmd in stage.Commands
		cmd.Cmd == "shell"
		i < run_index
	})
	cmd := stage.Commands[i]
}

# If the last SHELL before this RUN is a non-POSIX shell (e.g. pwsh, cmd.exe),
# we consider pipefail as active since these shells have different error handling
# and the check is not applicable.
stage_has_pipefail_active(stage, run_index) if {
	cmd := active_shell_before(stage, run_index)
	some prefix in non_posix_shells
	startswith(cmd.Value[0], prefix)
}

# If the last SHELL before this RUN explicitly sets -o pipefail,
# we consider pipefail as active.
stage_has_pipefail_active(stage, run_index) if {
	cmd := active_shell_before(stage, run_index)
	shell_has_pipefail(cmd.Value)
}

run_has_pipefail(val) if {
	cmds := sh.parse_commands(val)
	some cmd in cmds
	cmd == ["set", "-o", "pipefail"]
}

deny contains res if {
	some stage in input.Stages

	some run_index, run in stage.Commands
	run.Cmd == "run"

	not stage_has_pipefail_active(stage, run_index)

	some val in run.Value
	sh.has_pipes(val)
	not run_has_pipefail(val)

	res := result.new(
		"RUN instruction with a pipe should use 'set -o pipefail'",
		run,
	)
}
