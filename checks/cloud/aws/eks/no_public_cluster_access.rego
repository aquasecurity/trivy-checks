# METADATA
# title: EKS Clusters should have the public access disabled
# description: |
#   EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
# custom:
#   id: AVD-AWS-0040
#   avd_id: AVD-AWS-0040
#   provider: aws
#   service: eks
#   severity: CRITICAL
#   short_code: no-public-cluster-access
#   recommended_action: Don't enable public access to EKS Clusters
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: eks
#             provider: aws
#   examples: checks/cloud/aws/eks/no_public_cluster_access.yaml
package builtin.aws.eks.aws0040

import rego.v1

deny contains res if {
	some cluster in input.aws.eks.clusters
	cluster.publicaccessenabled.value == true
	res := result.new("Public cluster access is enabled.", cluster.publicaccessenabled)
}
