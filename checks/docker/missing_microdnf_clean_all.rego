# METADATA
# title: "'microdnf clean all' missing"
# description: "Cached package data should be cleaned after installation to reduce image size."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
# custom:
#   id: DS-0027
#   aliases:
#     - AVD-DS-0027
#     - DS027
#     - purge-microdnf-package-cache
#   long_id: docker-purge-microdnf-package-cache
#   severity: HIGH
#   recommended_action: "Add 'microdnf clean all' to Dockerfile"
#   input:
#     selector:
#       - type: dockerfile
package builtin.dockerfile.DS027

import rego.v1

import data.lib.docker

install_regex := `(microdnf install)|(microdnf reinstall)`

microdnf_regex := sprintf("%s|(microdnf clean all)", [install_regex])

get_dnf contains output if {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match(install_regex, arg)

	not contains_clean_after_dnf(arg)
	output := {
		"arg": arg,
		"cmd": run,
	}
}

deny contains res if {
	output := get_dnf[_]
	msg := sprintf("'microdnf clean all' is missed: %s", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_clean_after_dnf(cmd) if {
	dnf_commands := regex.find_n(microdnf_regex, cmd, -1)

	dnf_commands[count(dnf_commands) - 1] == "microdnf clean all"
}
