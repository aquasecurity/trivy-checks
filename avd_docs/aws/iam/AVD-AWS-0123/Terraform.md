
Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced

```hcl
resource "aws_iam_group" "support" {
  name =  "support"
}
resource "aws_iam_group_policy" "mfa" {
   
    group = aws_iam_group.support.name
    policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
          "Bool": {
              "aws:MultiFactorAuthPresent": ["true"]
          }
      }
    }
  ]
}
EOF
}

```

#### Remediation Links
 - https://registry.terraform.io/modules/terraform-module/enforce-mfa/aws/latest

 - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details

