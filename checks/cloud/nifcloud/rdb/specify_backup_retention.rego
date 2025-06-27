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
#   id: NIF-0009
#   aliases:
#     - AVD-NIF-0009
#     - specify-backup-retention
#   long_id: nifcloud-rdb-specify-backup-retention
#   provider: nifcloud
#   service: rdb
#   severity: MEDIUM
#   recommended_action: Explicitly set the retention period to greater than the default
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rdb
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/rdb/specify_backup_retention.yaml
package builtin.nifcloud.rdb.nifcloud0009

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some db in input.nifcloud.rdb.dbinstances
	value.less_than(db.backupretentionperioddays, 2)
	res := result.new("Instance has very low backup retention period.", db.backupretentionperioddays)
}
