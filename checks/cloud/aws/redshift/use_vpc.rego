# METADATA
# title: Redshift cluster should be deployed into a specific VPC
# description: |
#   Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tenant.
#   In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html
# custom:
#   id: AWS-0127
#   aliases:
#     - AVD-AWS-0127
#     - use-vpc
#   long_id: aws-redshift-use-vpc
#   provider: aws
#   service: redshift
#   severity: HIGH
#   recommended_action: Deploy Redshift cluster into a non default VPC
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: redshift
#             provider: aws
#   examples: checks/cloud/aws/redshift/use_vpc.yaml
package builtin.aws.redshift.aws0127

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.redshift.clusters
	subnet_group_name_missed(cluster)
	res := result.new(
		"Cluster is deployed outside of a VPC.",
		object.get(cluster, "subnetgroupname", cluster),
	)
}

subnet_group_name_missed(cluster) if value.is_empty(cluster.subnetgroupname)

subnet_group_name_missed(cluster) if not cluster.subnetgroupname
