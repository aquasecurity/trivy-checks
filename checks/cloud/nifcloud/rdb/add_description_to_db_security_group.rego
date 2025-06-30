# METADATA
# title: Missing description for db security group.
# description: |
#   DB security groups should include a description for auditing purposes.
#
#   Simplifies auditing, debugging, and managing db security groups.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/rdb/fw_new.htm
# custom:
#   id: AVD-NIF-0012
#   avd_id: AVD-NIF-0012
#   aliases:
#     - nifcloud-rdb-add-description-to-db-security-group
#   provider: nifcloud
#   service: rdb
#   severity: LOW
#   short_code: add-description-to-db-security-group
#   recommended_action: Add descriptions for all db security groups
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rdb
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/rdb/add_description_to_db_security_group.yaml
package builtin.nifcloud.rdb.nifcloud0012

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some sg in input.nifcloud.rdb.dbsecuritygroups
	isManaged(sg)
	without_description(sg)
	res := result.new("DB security group does not have a description.", sg.description)
}

deny contains res if {
	some sg in input.nifcloud.rdb.dbsecuritygroups
	isManaged(sg)
	sg.description.value == "Managed by Terraform"
	res := result.new("DB security group explicitly uses the default description.", sg.description)
}

without_description(sg) if value.is_empty(sg.description)

without_description(sg) if not sg.description
