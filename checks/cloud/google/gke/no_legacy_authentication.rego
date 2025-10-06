# METADATA
# title: Legacy client authentication methods utilized.
# description: |
#   It is recommended to use Service Accounts and OAuth as authentication methods for accessing the master in the container cluster.
#
#   Basic authentication should be disabled by explicitly unsetting the <code>username</code> and <code>password</code> on the <code>master_auth</code> block.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods
# custom:
#   id: AVD-GCP-0064
#   avd_id: AVD-GCP-0064
#   provider: google
#   service: gke
#   severity: HIGH
#   short_code: no-legacy-authentication
#   recommended_action: Use service account or OAuth for authentication
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: gke
#             provider: google
#   examples: checks/cloud/google/gke/no_legacy_authentication.yaml
package builtin.google.gke.google0064

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	cluster.masterauth.clientcertificate.issuecertificate.value
	res := result.new(
		"Cluster allows the use of certificates for master authentication.",
		cluster.masterauth.clientcertificate.issuecertificate,
	)
}

deny contains res if {
	some cluster in input.google.gke.clusters
	isManaged(cluster)
	not cluster.masterauth.clientcertificate.issuecertificate.value
	value.is_not_empty(cluster.masterauth.username)
	res := result.new(
		"Cluster allows the use of basic auth for master authentication.",
		cluster.masterauth.username,
	)
}
