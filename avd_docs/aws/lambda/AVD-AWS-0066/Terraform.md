
Enable tracing

```hcl
resource "aws_lambda_function" "good_example" {
  filename         = "lambda_function_payload.zip"
  function_name    = "lambda_function_name"
  role             = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  handler          = "exports.test"
  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs12.x"
  tracing_config {
    mode = "Active"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#mode

