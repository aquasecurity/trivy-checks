
Activity could be happening in your account in a different region. When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operating in.


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html


