# METADATA
# title: "Image user should not be 'root'"
# description: "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
# custom:
#   id: DS-0002
#   aliases:
#     - AVD-DS-0002
#     - DS002
#     - least-privilege-user
#   long_id: docker-least-privilege-user
#   severity: HIGH
#   recommended_action: "Add 'USER <non root user name>' line to the Dockerfile"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/root_user.yaml
package builtin.dockerfile.DS002

import rego.v1

import data.lib.docker

# get_user returns all the usernames from
# the USER command.
get_user contains username if {
	user := docker.user[_]
	username := user.Value[_]
}

# fail_user_count is true if there is no USER command.
fail_user_count if {
	count(get_user) < 1
}

# fail_last_user_root is true if the last USER command
# value is "root"
fail_last_user_root contains lastUser if {
	users := [user | user := docker.user[_]]
	lastUser := users[count(users) - 1]
	regex.match("^root(:.+){0,1}$", lastUser.Value[0])
}

# fail_last_user_root is true if the last USER command
# value is "0"
fail_last_user_root contains lastUser if {
	users := [user | user := docker.user[_]]
	lastUser := users[count(users) - 1]
	regex.match("^0(:.+){0,1}$", lastUser.Value[0])
}

deny contains res if {
	fail_user_count
	msg := "Specify at least 1 USER command in Dockerfile with non-root user as argument"
	res := result.new(msg, {})
}

deny contains res if {
	cmd := fail_last_user_root[_]
	msg := "Last USER command in Dockerfile should not be 'root'"
	res := result.new(msg, cmd)
}
