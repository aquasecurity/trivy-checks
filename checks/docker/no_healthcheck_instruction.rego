# METADATA
# title: "No HEALTHCHECK defined"
# description: "You should add HEALTHCHECK instruction in your docker container images to perform the health check on running containers."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://blog.aquasec.com/docker-security-best-practices
# custom:
#   id: DS-0026
#   aliases:
#     - AVD-DS-0026
#     - DS026
#     - no-healthcheck
#   long_id: docker-no-healthcheck
#   severity: LOW
#   recommended_action: "Add HEALTHCHECK instruction in Dockerfile"
#   input:
#     selector:
#       - type: dockerfile
package builtin.dockerfile.DS026

import rego.v1

import data.lib.docker

deny contains res if {
	count(docker.healthcheck) == 0
	msg := "Add HEALTHCHECK instruction in your Dockerfile"
	res := result.new(msg, {})
}
