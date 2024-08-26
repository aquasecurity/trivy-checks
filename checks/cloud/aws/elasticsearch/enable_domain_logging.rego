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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type
#     good_examples: checks/cloud/aws/elasticsearch/enable_domain_logging.tf.go
#     bad_examples: checks/cloud/aws/elasticsearch/enable_domain_logging.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/elasticsearch/enable_domain_logging.cf.go
#     bad_examples: checks/cloud/aws/elasticsearch/enable_domain_logging.cf.go
package builtin.aws.elasticsearch.aws0042

import rego.v1

deny contains res if {
	some domain in input.aws.elasticsearch.domains
	domain.logpublishing.auditenabled.value == false
	res := result.new("Domain audit logging is not enabled.", domain.logpublishing.auditenabled)
}
