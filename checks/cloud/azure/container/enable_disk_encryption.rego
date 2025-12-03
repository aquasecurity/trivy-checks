# METADATA
# title: Ensure AKS cluster has disk encryption set ID configured
# description: |
#   Azure Kubernetes clusters should define a disk encryption set ID to ensure encrypted storage for OS and data disks. This provides an additional layer of security by encrypting data at rest.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#disk_encryption_set_id
# custom:
#   id: AZU-0067
#   long_id: azure-container-enable-disk-encryption
#   aliases:
#     - AVD-AZU-0067
#     - enable-disk-encryption
#   provider: azure
#   service: container
#   severity: LOW
#   recommended_action: Configure a disk encryption set ID for the AKS cluster to enable customer-managed key encryption.
#   minimum_trivy_version: 0.68.0
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: container
#             provider: azure
#   examples: checks/cloud/azure/container/enable_disk_encryption.yaml
package builtin.azure.container.azure0067

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some cluster in input.azure.container.kubernetesclusters
	isManaged(cluster)
	is_disk_encryption_missing(cluster)
	res := result.new(
		"Cluster does not have disk encryption set ID configured.",
		metadata.obj_by_path(cluster, ["diskencryptionsetid"]),
	)
}

is_disk_encryption_missing(cluster) if not cluster.diskencryptionsetid
is_disk_encryption_missing(cluster) if value.is_empty(cluster.diskencryptionsetid)
