# METADATA
# title: "Exposed port out of range"
# description: "UNIX ports outside the range 0-65535 are exposed."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/engine/reference/builder/#expose
# custom:
#   id: DS-0008
#   aliases:
#     - AVD-DS-0008
#     - DS008
#     - port-out-of-range
#   long_id: docker-port-out-of-range
#   severity: CRITICAL
#   recommended_action: "Use port number within range"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/unix_ports_out_of_range.yaml
package builtin.dockerfile.DS008

import rego.v1

import data.lib.docker

invalid_ports contains output if {
	expose := docker.expose[_]
	port := to_number(split(expose.Value[_], "/")[0])
	port > 65535
	output := {
		"port": port,
		"cmd": expose,
	}
}

deny contains res if {
	output := invalid_ports[_]
	msg := sprintf("'EXPOSE' contains port which is out of range [0, 65535]: %d", [output.port])
	res := result.new(msg, output.cmd)
}
