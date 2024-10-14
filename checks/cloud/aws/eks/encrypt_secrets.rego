# METADATA
# title: EKS should have the encryption of secrets enabled
# description: |
#   EKS cluster resources should have the encryption_config block set with protection of the secrets resource.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/
# custom:
#   id: AVD-AWS-0039
#   avd_id: AVD-AWS-0039
#   provider: aws
#   service: eks
#   severity: HIGH
#   short_code: encrypt-secrets
#   recommended_action: Enable encryption of EKS secrets
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: eks
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config
#     good_examples: checks/cloud/aws/eks/encrypt_secrets.yaml
#     bad_examples: checks/cloud/aws/eks/encrypt_secrets.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/eks/encrypt_secrets.yaml
#     bad_examples: checks/cloud/aws/eks/encrypt_secrets.yaml
package builtin.aws.eks.aws0039

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.eks.clusters
	secret_encryption_not_enabled(cluster)
	res := result.new(
		"Cluster does not have secret encryption enabled.",
		metadata.obj_by_path(cluster, ["encryption", "secrets"]),
	)
}

deny contains res if {
	some cluster in input.aws.eks.clusters
	cluster.encryption.secrets.value
	without_cmk(cluster)
	res := result.new(
		"Cluster encryption requires a KMS key ID, which is missing",
		metadata.obj_by_path(cluster, ["encryption", "kmskeyid"]),
	)
}

secret_encryption_not_enabled(cluster) if value.is_false(cluster.encryption.secrets)

secret_encryption_not_enabled(cluster) if not cluster.encryption.secrets

without_cmk(cluster) if value.is_empty(cluster.encryption.kmskeyid)

without_cmk(cluster) if not cluster.encryption.kmskeyid
