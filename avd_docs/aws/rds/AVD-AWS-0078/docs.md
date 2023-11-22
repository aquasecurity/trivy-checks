
Amazon RDS uses the AWS managed key for your new DB instance. For complete control over KMS keys, including establishing and maintaining their key policies, IAM policies, and grants, enabling and disabling them, and rotating their cryptographic material, use a customer managed keys.

The encryption key specified in `performance_insights_kms_key_id` references a KMS ARN

### Impact
Using AWS managed keys does not allow for fine grained control

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.access-control.html#USER_PerfInsights.access-control.cmk-policy

- https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-mgmt


