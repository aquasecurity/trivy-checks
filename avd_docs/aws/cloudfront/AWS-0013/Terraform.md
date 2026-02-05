
Use the most modern TLS/SSL policies available

```hcl
resource "aws_cloudfront_distribution" "good_example" {
  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version       = "TLSv1.2_2025"
  }
}
```
```hcl
resource "aws_cloudfront_distribution" "good_example" {
  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version       = "TLSv1.3_2025"
  }
}
```
```hcl
resource "aws_cloudfront_distribution" "good_example" {
  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version       = "TLSv1.2_2021"
  }
}
```
```hcl
resource "aws_cloudfront_distribution" "good_example" {
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.0"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#minimum_protocol_version

