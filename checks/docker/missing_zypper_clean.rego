# METADATA
# title: "'zypper clean' missing"
# description: "The layer and image size should be reduced by deleting unneeded caches after running zypper."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# custom:
#   id: DS-0020
#   aliases:
#     - AVD-DS-0020
#     - DS020
#     - purge-zipper-cache
#   long_id: docker-purge-zipper-cache
#   severity: HIGH
#   recommended_action: "Add 'zypper clean' to Dockerfile"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/missing_zypper_clean.yaml
package builtin.dockerfile.DS020

import rego.v1

import data.lib.docker

install_regex := `(zypper in)|(zypper remove)|(zypper rm)|(zypper source-install)|(zypper si)|(zypper patch)|(zypper (-(-)?[a-zA-Z]+ *)*install)`

zypper_regex := sprintf("%s|(zypper clean)|(zypper cc)", [install_regex])

get_zypper contains output if {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match(install_regex, arg)

	not contains_zipper_clean(arg)
	output := {
		"arg": arg,
		"cmd": run,
	}
}

deny contains res if {
	output := get_zypper[_]
	msg := sprintf("'zypper clean' is missed: '%s'", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_zipper_clean(cmd) if {
	zypper_commands := regex.find_n(zypper_regex, cmd, -1)

	is_zypper_clean(zypper_commands[count(zypper_commands) - 1])
}

is_zypper_clean(cmd) if {
	cmd == "zypper clean"
}

is_zypper_clean(cmd) if {
	cmd == "zypper cc"
}
