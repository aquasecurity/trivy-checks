# METADATA
# title: SSH Keys are the preferred way to connect to your droplet, no keys are supplied
# description: |
#   When working with a server, you’ll likely spend most of your time in a terminal session connected to your server through SSH. A more secure alternative to password-based logins, SSH keys use encryption to provide a secure way of logging into your server and are recommended for all users.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.digitalocean.com/community/tutorials/understanding-the-ssh-encryption-and-connection-process
# custom:
#   id: AVD-DIG-0004
#   avd_id: AVD-DIG-0004
#   provider: digitalocean
#   service: compute
#   severity: HIGH
#   short_code: use-ssh-keys
#   recommended_action: Use ssh keys for login
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: digitalocean
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/droplet#ssh_keys
#     good_examples: checks/cloud/digitalocean/compute/use_ssh_keys.yaml
#     bad_examples: checks/cloud/digitalocean/compute/use_ssh_keys.yaml
package builtin.digitalocean.compute.digitalocean0004

import rego.v1

deny contains res if {
	some droplet in input.digitalocean.compute.droplets
	isManaged(droplet)
	not has_keys(droplet)
	res := result.new(
		"Droplet does not have an SSH key specified.",
		droplet,
	)
}

has_keys(drolet) := count(drolet.sshkeys) > 0
