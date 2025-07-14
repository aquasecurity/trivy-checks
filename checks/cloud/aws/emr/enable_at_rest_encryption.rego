# METADATA
# title: Enable at-rest encryption for EMR clusters.
# description: |
#   Data stored within an EMR cluster should be encrypted to ensure sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html
# custom:
#   id: AWS-0137
#   aliases:
#     - AVD-AWS-0137
#     - enable-at-rest-encryption
#   long_id: aws-emr-enable-at-rest-encryption
#   provider: aws
#   service: emr
#   severity: HIGH
#   recommended_action: Enable at-rest encryption for EMR cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: emr
#             provider: aws
#   examples: checks/cloud/aws/emr/enable_at_rest_encryption.yaml
package builtin.aws.emr.aws0137

import rego.v1

deny contains res if {
	some sec_conf in input.aws.emr.securityconfiguration
	vars := json.unmarshal(sec_conf.configuration.value)
	vars.EncryptionConfiguration.EnableAtRestEncryption == false
	res := result.new("EMR cluster does not have at-rest encryption enabled.", sec_conf.configuration)
}
