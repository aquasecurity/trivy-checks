# METADATA
# title: Domain logging should be enabled for Elastic Search domains
# description: |
#   Amazon ES exposes four Elasticsearch logs through Amazon CloudWatch Logs: error logs, search slow logs, index slow logs, and audit logs.
#   Search slow logs, index slow logs, and error logs are useful for troubleshooting performance and stability issues.
#   Audit logs track user activity for compliance purposes.
#   All the logs are disabled by default.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html
# custom:
#   id: AVD-AWS-0042
#   avd_id: AVD-AWS-0042
#   provider: aws
#   service: elasticsearch
#   severity: MEDIUM
#   short_code: enable-domain-logging
#   recommended_action: Enable logging for ElasticSearch domains
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticsearch
#             provider: aws
#   examples: checks/cloud/aws/elasticsearch/enable_domain_logging.yaml
package builtin.aws.elasticsearch.aws0042

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	not domain.logpublishing.auditenabled.value
	res := result.new(
		"Domain audit logging is not enabled.",
		metadata.obj_by_path(domain, ["logpublishing", "auditenabled"]),
	)
}
