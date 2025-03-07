
Enable logging to CloudWatch

```hcl
resource "aws_cloudtrail" "good_example" {
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.example.arn}:*"
}

resource "aws_cloudwatch_log_group" "example" {
  name = "Example"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail

