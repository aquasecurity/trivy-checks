# METADATA
# title: Delete expired TLS certificates
# description: |
#   Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be
#
#   deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can
#
#   damage the credibility of the application/website behind the ELB. As a best practice, it is
#
#   recommended to delete expired certificates.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://console.aws.amazon.com/iam/
# custom:
#   id: AWS-0168
#   aliases:
#     - AVD-AWS-0168
#     - remove-expired-certificates
#   long_id: aws-iam-remove-expired-certificates
#   provider: aws
#   service: iam
#   severity: LOW
#   recommended_action: Remove expired certificates
#   frameworks:
#     cis-aws-1.4:
#       - "1.19"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0168

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some certificate in input.aws.iam.servercertificates
	not value.is_unresolvable(certificate.expiration)
	time.parse_rfc3339_ns(certificate.expiration.value) < time.now_ns()
	res := result.new("Certificate has expired", certificate)
}
