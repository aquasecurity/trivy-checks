# METADATA
# title: BigQuery datasets should only be accessible within the organisation
# description: |
#   Using 'allAuthenticatedUsers' provides any GCP user - even those outside of your organisation - access to your BigQuery dataset.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-GCP-0046
#   avd_id: AVD-GCP-0046
#   provider: google
#   service: bigquery
#   severity: CRITICAL
#   short_code: no-public-access
#   recommended_action: Configure access permissions with higher granularity
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: bigquery
#             provider: google
#   examples: checks/cloud/google/bigquery/no_public_access.yaml
package builtin.google.bigquery.google0046

import rego.v1

deny contains res if {
	some dataset in input.google.bigquery.datasets
	some grant in dataset.accessgrants
	grant.specialgroup.value == "allAuthenticatedUsers"
	res := result.new("Dataset grants access to all authenticated GCP users.", grant.specialgroup)
}
