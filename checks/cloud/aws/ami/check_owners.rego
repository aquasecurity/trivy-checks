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
#   id: AVD-AWS-0344
#   avd_id: AVD-AWS-0344
#   provider: aws
#   service: ami
#   severity: LOW
#   short_code: ensure-ami-has-owners
#   recommended_action: Specify the owners field in the AWS AMI data source configuration
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ami
#             provider: aws

package builtin.aws.ami.aws0344

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	ami := input.aws.ami

	owners_not_specified(ami)
	res := result.new("AWS AMI data source should specify owners to ensure AMIs come from trusted sources", ami)
}

owners_not_specified(ami) if {
	not ami.owners
}

owners_not_specified(ami) if {
	count(ami.owners) == 0
}
#