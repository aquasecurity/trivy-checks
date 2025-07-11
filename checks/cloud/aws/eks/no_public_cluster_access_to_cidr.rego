# METADATA
# title: EKS cluster should not have open CIDR range for public access
# description: |
#   EKS Clusters have public access cidrs set to 0.0.0.0/0 by default which is wide open to the internet. This should be explicitly set to a more specific private CIDR range
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html
# custom:
#   id: AWS-0041
#   aliases:
#     - AVD-AWS-0041
#     - no-public-cluster-access-to-cidr
#   long_id: aws-eks-no-public-cluster-access-to-cidr
#   provider: aws
#   service: eks
#   severity: CRITICAL
#   recommended_action: Don't enable public access to EKS Clusters
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: eks
#             provider: aws
#   examples: checks/cloud/aws/eks/no_public_cluster_access_to_cidr.yaml
package builtin.aws.eks.aws0041

import rego.v1

deny contains res if {
	some cluster in input.aws.eks.clusters
	cluster.publicaccessenabled.value == true
	some c in cluster.publicaccesscidrs
	cidr.is_public(c.value)
	message := sprintf("Cluster allows access from a public CIDR: %s", [c.value])
	res := result.new(message, c)
}
