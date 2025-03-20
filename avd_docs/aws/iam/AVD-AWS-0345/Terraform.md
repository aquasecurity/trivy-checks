
Create more restrictive S3 policies instead of using s3:*

```hcl
resource "aws_iam_policy" "good_policy" {
  name = "good_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::examplebucket/*"
      }
    ]
  })
}

resource "aws_iam_role" "good_role" {
  name = "good_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "good_role_policy_attachment" {
  role       = aws_iam_role.good_role.name
  policy_arn = aws_iam_policy.good_policy.arn
}
```


