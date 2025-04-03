
Enable encryption of EBS volumes

```hcl
resource "aws_ebs_volume" "good_example" {
  encrypted = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted

