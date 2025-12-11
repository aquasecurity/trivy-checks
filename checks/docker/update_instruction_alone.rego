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
#   examples: checks/docker/update_instruction_alone.yaml
package builtin.dockerfile.DS017

import rego.v1

import data.lib.docker

install_cmds := {
	"upgrade",
	"install",
	"source-install",
	"reinstall",
	"groupinstall",
	"localinstall",
	"add",
}

update_cmds := {
	"update",
	"up",
}

package_managers := {
	{"apt-get", "apt"},
	{"yum"},
	{"apk"},
	{"dnf"},
	{"zypper"},
}

deny contains res if {
	run := docker.run[_]
	run_cmd := concat(" ", run.Value)
	cmds := docker.split_cmd(run_cmd)

	some package_manager
	update_indexes := has_update(cmds, package_managers[package_manager])
	not update_followed_by_install(cmds, package_manager, update_indexes)

	msg := "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
	res := result.new(msg, run)
}

has_update(cmds, package_manager) := indexes if {
	indexes := docker.command_indexes(cmds, update_cmds, package_manager)
}

update_followed_by_install(cmds, package_manager, update_indexes) if {
	install_index := docker.command_indexes(cmds, install_cmds, package_manager)
	update_indexes[_] < install_index[_]
}
