# METADATA
# title: "WORKDIR should not be mounted on system dirs"
# description: "WORKDIR should not be mounted on system directories to avoid container breakouts"
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir
# custom:
#   id: DS-0030
#   aliases:
#     - AVD-DS-0030
#     - DS030
#     - avoid-sys-workdir-mounts
#   long_id: docker-avoid-sys-workdir-mounts
#   severity: HIGH
#   recommended_action: "Avoid using system directories to mount WORKDIR"
#   input:
#     selector:
#       - type: dockerfile
package builtin.dockerfile.DS030

import rego.v1

import data.lib.docker

sysdirs := {"/proc/", "/boot/", "/dev/", "/initrd/", "/lost+found/"}

is_workdir_in_sysdirs contains output if {
	workdir := docker.workdir[_]
	arg := workdir.Value[0]

	trimmed := trim(arg, "\"")
	startswith(trimmed, sysdirs[_])
	output := {
		"cmd": workdir,
		"arg": arg,
	}
}

deny contains res if {
	output := is_workdir_in_sysdirs[_]
	msg := sprintf("WORKDIR path '%s' should not mount system directories", [output.arg])
	res := result.new(msg, output.cmd)
}
