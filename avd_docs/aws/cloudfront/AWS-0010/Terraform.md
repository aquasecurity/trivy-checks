
Enable logging for CloudFront distributions

```hcl
resource "aws_cloudfront_distribution" "good_example" {
  // other config
  logging_config {
    include_cookies = false
    bucket          = "mylogs.s3.amazonaws.com"
    prefix          = "myprefix"
  }
}
```
```hcl
resource "aws_cloudfront_distribution" "good_v2_example" {
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
  viewer_certificate {
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_cloudwatch_log_delivery_source" "example" {
  log_type     = "ACCESS_LOGS"
  resource_arn = aws_cloudfront_distribution.good_v2_example.arn
}

resource "aws_cloudwatch_log_delivery" "example" {
  delivery_source_name = aws_cloudwatch_log_delivery_source.example.name
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config

