# METADATA
# title: Enable in-transit encryption for EMR clusters.
# description: |
#   Data stored within an EMR cluster should be encrypted to ensure sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html
# custom:
#   id: AVD-AWS-0138
#   avd_id: AVD-AWS-0138
#   provider: aws
#   service: emr
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: Enable in-transit encryption for EMR cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: emr
#             provider: aws
#   examples: checks/cloud/aws/emr/enable_in_transit_encryption.yaml
package builtin.aws.emr.aws0138

import rego.v1

deny contains res if {
	some sec_conf in input.aws.emr.securityconfiguration
	vars := json.unmarshal(sec_conf.configuration.value)
	vars.EncryptionConfiguration.EnableInTransitEncryption == false
	res := result.new("EMR cluster does not have in-transit encryption enabled.", sec_conf.configuration)
}
