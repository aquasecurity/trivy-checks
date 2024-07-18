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
#   id: AVD-AWS-0168
#   avd_id: AVD-AWS-0168
#   provider: aws
#   service: iam
#   severity: LOW
#   short_code: remove-expired-certificates
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

deny contains res if {
	some certificate in input.aws.iam.servercertificates
	time.parse_rfc3339_ns(certificate.expiration.value) < time.now_ns()

	res := result.new("Certificate has expired", certificate)
}
