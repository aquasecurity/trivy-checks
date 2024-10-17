# METADATA
# title: Config configuration aggregator should be using all regions for source
# description: |
#   Sources that aren't covered by the aggregator are not include in the configuration. The configuration aggregator should be configured with all_regions for the source.
#   This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html
# custom:
#   id: AVD-AWS-0019
#   avd_id: AVD-AWS-0019
#   provider: aws
#   service: config
#   severity: HIGH
#   short_code: aggregate-all-regions
#   recommended_action: Set the aggregator to cover all regions
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: config
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions
#     good_examples: checks/cloud/aws/config/aggregate_all_regions.yaml
#     bad_examples: checks/cloud/aws/config/aggregate_all_regions.yaml
#   cloud_formation:
#     good_examples: checks/cloud/aws/config/aggregate_all_regions.yaml
#     bad_examples: checks/cloud/aws/config/aggregate_all_regions.yaml
package builtin.aws.config.aws0019

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	cfg_aggregator := input.aws.config.configurationaggregrator
	isManaged(cfg_aggregator)
	not cfg_aggregator.sourceallregions.value
	res := result.new(
		"Configuration aggregation is not set to source from all regions.",
		metadata.obj_by_path(cfg_aggregator, ["sourceallregions"]),
	)
}
