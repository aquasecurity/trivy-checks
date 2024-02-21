# METADATA
# title: "WORKDIR should not be mounted on system dirs"
# description: "WORKDIR should not be mounted on system directories to avoid container breakouts"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir
# custom:
#   id: DS030
#   avd_id: AVD-DS-0030
#   severity: HIGH
#   short_code: avoid-sys-workdir-mounts
#   recommended_action: "Avoid using system directories to mount WORKDIR"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS030

import data.lib.docker

sysdirs := {"/proc/", "/boot/", "/dev/", "/initrd/", "/lost+found/"}

is_workdir_in_sysdirs[output] {
	workdir := docker.workdir[_]
	arg := workdir.Value[0]

	trimmed := trim(arg, "\"")
	startswith(trimmed, sysdirs[_])
	output := {
		"cmd": workdir,
		"arg": arg,
	}
}

deny[res] {
	output := is_workdir_in_sysdirs[_]
	msg := sprintf("WORKDIR path '%s' should not mount system directories", [output.arg])
	res := result.new(msg, output.cmd)
}
