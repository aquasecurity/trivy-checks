# METADATA
# title: DocumentDB logs export should be enabled
# description: |
#   Document DB does not have auditing by default. To ensure that you are able to accurately audit the usage of your DocumentDB cluster you should enable export logs.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html
# custom:
#   aliases:
#     - aws-documentdb-enable-log-export
#   avd_id: AVD-AWS-0020
#   provider: aws
#   service: documentdb
#   severity: MEDIUM
#   short_code: enable-log-export
#   recommended_action: Enable export logs
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: documentdb
#             provider: aws
#   examples: checks/cloud/aws/documentdb/enable_log_export.yaml
package builtin.aws.documentdb.aws0020

import rego.v1

import data.lib.cloud.value

log_export_audit := "audit"

log_export_profiler := "profiler"

deny contains res if {
	some cluster in input.aws.documentdb.clusters
	not export_audit_or_profiler(cluster)
	res := result.new("Neither CloudWatch audit nor profiler log exports are enabled.", cluster)
}

export_audit_or_profiler(cluster) if {
	some log in cluster.enabledlogexports
	log.value in [log_export_audit, log_export_profiler]
}

export_audit_or_profiler(cluster) if {
	some log in cluster.enabledlogexports
	value.is_unresolvable(log)
}
