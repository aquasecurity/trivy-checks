# METADATA
# title: "'yum clean all' missing"
# description: "You should use 'yum clean all' after using a 'yum install' command to clean package cached data and reduce image size."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# custom:
#   id: DS015
#   avd_id: AVD-DS-0015
#   severity: HIGH
#   short_code: purge-yum-package-cache
#   recommended_action: "Add 'yum clean all' to Dockerfile"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS015

import future.keywords.in

import data.lib.docker

deny[res] {
	run := docker.run[_]
	run_cmd := concat(" ", run.Value)
	cmds := docker.split_cmd(run_cmd)

	install_indexes := has_install(cmds, {"yum"})
	not install_followed_by_clean(cmds, {"yum"}, install_indexes)

	msg := sprintf("'yum clean all' is missed: %s", [run_cmd])
	res := result.new(msg, run)
}

has_install(cmds, package_manager) = indexes {
	indexes := docker.command_indexes(cmds, ["install"], package_manager)
}

install_followed_by_clean(cmds, package_manager, install_indexes) {
	clean_indexes := docker.command_indexes(cmds, ["clean"], package_manager)
	clean_all_indexes = [idx | cmd := cmds[idx]; "all" in cmd]
	count(clean_all_indexes) > 0
	install_indexes[count(install_indexes) - 1] < clean_all_indexes[count(clean_all_indexes) - 1]
}
