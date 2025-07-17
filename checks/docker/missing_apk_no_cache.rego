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

import data.lib.cmdutil
import data.lib.docker

deny contains res if {
	some run in docker.run
	raw_cmd := cmdutil.to_command_string(run.Value)
	some tokens in sh.parse_commands(raw_cmd)
	cmdutil.is_tool(tokens, "apk")
	cmdutil.is_command(tokens, "add")
	not cmdutil.has_flag(tokens, "--no-cache")
	msg := sprintf("'--no-cache' is missed: %s", [raw_cmd])
	res := result.new(msg, run)
}
