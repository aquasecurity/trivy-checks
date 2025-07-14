# METADATA
# title: "'apt-get dist-upgrade' used"
# description: "'apt-get dist-upgrade' upgrades a major version so it doesn't make more sense in Dockerfile."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: DS-0024
#   aliases:
#     - AVD-DS-0024
#     - DS024
#     - no-dist-upgrade
#   long_id: docker-no-dist-upgrade
#   deprecated: true
#   severity: HIGH
#   recommended_action: "Just use different image"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/run_apt_get_dist_upgrade.yaml
package builtin.dockerfile.DS024

import rego.v1

import data.lib.docker

get_apt_get_dist_upgrade contains run if {
	run := docker.run[_]
	regex.match(`apt-get .* dist-upgrade`, run.Value[0])
}

deny contains res if {
	cmd := get_apt_get_dist_upgrade[_]
	msg := "'apt-get dist-upgrade' should not be used in Dockerfile"
	res := result.new(msg, cmd)
}
