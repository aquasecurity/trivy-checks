# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances and RDS Cluster instances are not launched into the public cloud."
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   id: AWS-0180
#   aliases:
#     - AVD-AWS-0180
#     - enable-public-access
#   long_id: aws-rds-enable-public-access
#   provider: aws
#   service: rds
#   severity: HIGH
#   recommended_action: "Remove the public endpoint from the RDS instance."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   examples: "checks/cloud/aws/rds/disable_public_access.yaml"
package builtin.aws.rds.aws0180

import rego.v1

deny contains res if {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}

deny contains res if {
	instance := input.aws.rds.clusters[_].instances[_].instance
	instance.publicaccess.value
	res := result.new("Cluster instance has Public Access enabled", instance.publicaccess)
}
