
Use the most modern TLS/SSL policies available

```hcl
resource "aws_elasticsearch_domain" "good_example" {
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
}
```
```hcl
resource "aws_elasticsearch_domain" "good_example_fips" {
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#tls_security_policy

