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
#   id: AVD-AWS-0041
#   avd_id: AVD-AWS-0041
#   provider: aws
#   service: eks
#   severity: CRITICAL
#   short_code: no-public-cluster-access-to-cidr
#   recommended_action: Don't enable public access to EKS Clusters
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: eks
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config
#     good_examples: checks/cloud/aws/eks/no_public_cluster_access_to_cidr.tf.go
#     bad_examples: checks/cloud/aws/eks/no_public_cluster_access_to_cidr.tf.go
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
