# METADATA
# title: AWS AMI data source should specify owners
# description: |
#   AWS AMI data source should specify owners to avoid using unverified AMIs.
#   The owners field helps ensure you're using AMIs from known and trusted sources.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami
# custom:
#   id: AWS-0344
#   aliases:
#     - AVD-AWS-0344
#     - ensure-ami-has-owners
#   long_id: aws-ec2-ensure-ami-has-owners
#   provider: aws
#   service: ec2
#   severity: LOW
#   minimum_trivy_version: 0.61.0
#   recommended_action: Specify the owners field in the AWS AMI data source configuration
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/specify_ami_owners.yaml
package builtin.aws.ec2.aws0344

import rego.v1

deny contains res if {
	some ami in input.aws.ec2.requestedamis
	owners_not_specified(ami)
	res := result.new("AWS AMI data source should specify owners to ensure AMIs come from trusted sources", ami)
}

owners_not_specified(ami) if not ami.owners

owners_not_specified(ami) if count(ami.owners) == 0
