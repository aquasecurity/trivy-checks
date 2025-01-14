# METADATA
# title: "'apk add' is missing '--no-cache'"
# description: "You should use 'apk add' with '--no-cache' to clean package cached data and reduce image size."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://github.com/gliderlabs/docker-alpine/blob/master/docs/usage.md#disabling-cache
# custom:
#   id: DS025
#   avd_id: AVD-DS-0025
#   severity: HIGH
#   short_code: purge-apk-package-cache
#   recommended_action: "Add '--no-cache' to 'apk add' in Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS025

import rego.v1

import data.lib.docker

get_apk contains output if {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match("apk (-[a-zA-Z]+\\s*)*add", arg)

	not contains_no_cache(arg)

	output := {
		"cmd": run,
		"arg": arg,
	}
}

deny contains res if {
	output := get_apk[_]
	msg := sprintf("'--no-cache' is missed: %s", [output.arg])
	res := result.new(msg, output.cmd)
}

contains_no_cache(cmd) if {
	split(cmd, " ")[_] == "--no-cache"
}
