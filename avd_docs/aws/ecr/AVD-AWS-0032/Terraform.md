
Do not allow public access in the policy

```hcl
resource "aws_ecr_repository" "example" {
  name = "bar"
}

resource "aws_ecr_repository_policy" "example" {
  repository = aws_ecr_repository.example.name
  policy     = <<EOF
 {
     "Version": "2008-10-17",
     "Statement": [
         {
             "Sid": "new policy",
             "Effect": "Allow",
             "Principal": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
             "Action": [
                 "ecr:SetRepositoryPolicy"
             ]
         }
     ]
 }
 EOF
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy#policy

