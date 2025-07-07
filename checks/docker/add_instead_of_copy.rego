# METADATA
# title: ADD instead of COPY
# description: You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.
# scope: package
# related_resources:
#   - https://docs.docker.com/engine/reference/builder/#add
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: DS-0005
#   aliases:
#     - AVD-DS-0005
#     - DS005
#     - use-copy-over-add
#   long_id: docker-use-copy-over-add
#   severity: LOW
#   recommended_action: Use COPY instead of ADD
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/add_instead_of_copy.yaml
package builtin.dockerfile.DS005

import rego.v1

import data.lib.docker

is_unnecessary_add(add) if {
	args := concat(" ", add.Value)
	every s in {".tar", "http://", "https://", "git@"} {
		not contains(args, s)
	}

	every prefix in {"file:", "multi:", "dir:"} {
		not is_command_with_hash(add.Value, prefix)
	}
}

is_command_with_hash(cmd, prefix) if {
	count(cmd) == 3
	startswith(cmd[0], prefix)
	cmd[1] == "in"
}

is_command_with_hash(cmd, prefix) if {
	count(cmd) == 2
	startswith(cmd[0], prefix)
}

deny contains res if {
	some add in docker.add
	is_unnecessary_add(add)
	args := concat(" ", add.Value)
	msg := sprintf("Consider using 'COPY %s' command instead of 'ADD %s'", [args, args])
	res := result.new(msg, add)
}
