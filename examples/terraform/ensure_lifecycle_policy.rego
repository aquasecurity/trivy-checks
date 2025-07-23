# METADATA
# title: Ensure lifecycle policies are defined for S3 buckets
# description: |
#   Lifecycle policies in S3 help manage object lifecycles by defining rules to transition objects to cheaper storage
#   or delete them after a certain period. This ensures cost optimization and data governance compliance.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration
# custom:
#   id: USR-TF-0001
#   avd_id: USR-TF-0001
#   severity: MEDIUM
#   short_code: ensure-lifecycle-policies
#   recommended_action: Define lifecycle policies for S3 buckets to manage object storage effectively.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package user.terraform.ensure_lifecycle_policy

import rego.v1

deny contains res if {
	some bucket in input.aws.s3.buckets
	not has_lifecycles(bucket)

	res := result.new(
		sprintf("S3 bucket '%s' does not have a lifecycle policy configured", [bucket.name.value]),
		bucket,
	)
}

has_lifecycles(bucket) if count(bucket.lifecycleconfiguration) > 0
