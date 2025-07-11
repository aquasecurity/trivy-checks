# METADATA
# title: "Port 22 exposed"
# description: "Exposing port 22 might allow users to SSH into the container."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: DS-0004
#   aliases:
#     - AVD-DS-0004
#     - DS004
#     - no-ssh-port
#   long_id: docker-no-ssh-port
#   severity: MEDIUM
#   recommended_action: "Remove 'EXPOSE 22' statement from the Dockerfile"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/port22.yaml
package builtin.dockerfile.DS004

import rego.v1

import data.lib.docker

# deny_list contains the port numbers which needs to be denied.
denied_ports := ["22", "22/tcp", "22/udp"]

# fail_port_check is true if the Dockerfile contains an expose statement for value 22
fail_port_check contains expose if {
	expose := docker.expose[_]
	expose.Value[_] == denied_ports[_]
}

deny contains res if {
	cmd := fail_port_check[_]
	msg := "Port 22 should not be exposed in Dockerfile"
	res := result.new(msg, cmd)
}
