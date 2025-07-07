# METADATA
# title: Default security group should restrict all traffic
# description: |
#   Configuring all VPC default security groups to restrict all traffic will encourage least
#
#   privilege security group development and mindful placement of AWS resources into
#
#   security groups which will in-turn reduce the exposure of those resources.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/default-custom-security-groups.html
# custom:
#   id: AVD-AWS-0173
#   avd_id: AVD-AWS-0173
#   provider: aws
#   service: ec2
#   severity: LOW
#   short_code: restrict-all-in-default-sg
#   recommended_action: Configure default security group to restrict all traffic
#   frameworks:
#     cis-aws-1.4:
#       - "5.3"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
package builtin.aws.ec2.aws0173

import rego.v1

deny contains res if {
	some sg in input.aws.ec2.vpcs[_].securitygroups
	sg.isdefault.value == true
	has_rules(sg)
	res := result.new("Default security group for VPC has ingress or egress rules.", sg)
}

has_rules(sg) if count(sg.ingressrules) > 0

has_rules(sg) if count(sg.egressrules) > 0
