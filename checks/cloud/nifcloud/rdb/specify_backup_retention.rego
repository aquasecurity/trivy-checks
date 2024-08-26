# METADATA
# title: RDB instance should have backup retention longer than 1 day
# description: |
#   Backup retention periods should be set to a period that is a balance on cost and limiting risk.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/spec/rdb/snapshot_backup.htm
# custom:
#   id: AVD-NIF-0009
#   avd_id: AVD-NIF-0009
#   provider: nifcloud
#   service: rdb
#   severity: MEDIUM
#   short_code: specify-backup-retention
#   recommended_action: Explicitly set the retention period to greater than the default
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rdb
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#backup_retention_period
#     good_examples: checks/cloud/nifcloud/rdb/specify_backup_retention.tf.go
#     bad_examples: checks/cloud/nifcloud/rdb/specify_backup_retention.tf.go
package builtin.nifcloud.rdb.nifcloud0009

import rego.v1

deny contains res if {
	some db in input.nifcloud.rdb.dbinstances
	db.backupretentionperioddays.value < 2
	res := result.new("Instance has very low backup retention period.", db.backupretentionperioddays)
}
