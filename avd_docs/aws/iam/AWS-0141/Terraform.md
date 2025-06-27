
Use lower privileged accounts instead, so only required privileges are available.

```hcl
resource "aws_iam_user" "test" {
  name = "lowprivuser"
}

resource "aws_iam_access_key" "test" {
  user = aws_iam_user.test.name
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key

