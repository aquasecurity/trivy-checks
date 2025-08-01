# METADATA
# title: "RUN using 'sudo'"
# description: "Avoid using 'RUN' with 'sudo' commands, as it can lead to unpredictable behavior."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/engine/reference/builder/#run
# custom:
#   id: DS-0010
#   aliases:
#     - AVD-DS-0010
#     - DS010
#     - no-sudo-run
#   long_id: docker-no-sudo-run
#   severity: CRITICAL
#   recommended_action: "Don't use sudo"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/run_using_sudo.yaml
package builtin.dockerfile.DS010

import rego.v1

import data.lib.docker

has_sudo(commands) if {
	parts = split(commands, "&&")

	instruction := parts[_]
	regex.match(`^\s*sudo`, instruction)
}

get_sudo contains run if {
	run = docker.run[_]
	count(run.Value) == 1
	arg := run.Value[0]
	has_sudo(arg)
}

deny contains res if {
	cmd := get_sudo[_]
	msg := "Using 'sudo' in Dockerfile should be avoided"
	res := result.new(msg, cmd)
}
