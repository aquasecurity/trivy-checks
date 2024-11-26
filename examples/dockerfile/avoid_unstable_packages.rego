# METADATA
# title: Avoid installing packages without specific versions
# description: |
#   Installing packages without specifying the version can lead to instability or unexpected behavior.
#   Always specify the exact version of the package to ensure predictable builds and avoid pulling in unintended updates.
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get
# custom:
#   id: USR-DF-0001
#   avd_id: USR-DF-0001
#   severity: HIGH
#   short_code: avoid-unstable-packages
#   recommended_action: Specify the exact version of packages when using RUN instructions.
#   input:
#     selector:
#       - type: dockerfile
package user.dockerfile.avoid_unstable_packages

import rego.v1

deny contains res if {
	some stage in input.Stages
	some instruction in stage.Commands

	instruction.Cmd == "run"

	some val in instruction.Value

	# custom function
	cmds := sh.parse_commands(val)

	some cmd in cmds
	cmd[0] == "apt-get"
	cmd[1] == "install"

	args := array.slice(cmd, 2, count(cmd))

	some arg in args

	# skip flags
	not startswith(arg, "-")
	not contains(arg, "=")

	res := result.new(
		sprintf("Avoid installing package %q without specifying a version.", [arg]),
		{},
	)
}
