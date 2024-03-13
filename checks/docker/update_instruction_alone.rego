# METADATA
# title: "'RUN <package-manager> update' instruction alone"
# description: "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/instructions/#run
# custom:
#   id: DS017
#   avd_id: AVD-DS-0017
#   severity: HIGH
#   short_code: no-orphan-package-update
#   recommended_action: "Combine '<package-manager> update' and '<package-manager> install' instructions to single one"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS017

import data.lib.docker

install_cmds = {
	"upgrade",
	"install",
	"source-install",
	"reinstall",
	"groupinstall",
	"localinstall",
	"add",
}

update_cmds = {
	"update",
	"up",
}

package_managers = {
	{"apt-get", "apt"},
	{"yum"},
	{"apk"},
	{"dnf"},
	{"zypper"},
}

deny[res] {
	run := docker.run[_]
	run_cmd := concat(" ", run.Value)
	cmds := regex.split(`\s*&&\s*`, run_cmd)

	update_res = has_update(cmds)
	not update_followed_by_install(cmds, update_res)

	msg := "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
	res := result.new(msg, run)
}

has_update(cmds) = {
	"package_manager": package_manager,
	"cmd_index": index,
} {
	index := contains_cmd_with_package_manager(cmds, update_cmds, package_managers[package_manager])
}

update_followed_by_install(cmds, update_res) {
	install_index := contains_cmd_with_package_manager(cmds, install_cmds, update_res.package_manager)
	update_res.cmd_index < install_index
}

contains_cmd_with_package_manager(cmds, cmds_to_check, package_manager) = cmd_index {
	cmd_parts := split(cmds[cmd_index], " ")
	some i, j
	cmd_parts[i] == package_manager[_]
	cmd_parts[j] == cmds_to_check[_]
	i < j
}
