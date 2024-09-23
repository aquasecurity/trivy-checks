package cloudwatch

var terraformLogGroupCustomerKeyGoodExamples = []string{
	`
resource "aws_kms_key" "cloudwatch" {
  enable_key_rotation = true
}

resource "aws_kms_alias" "cloudwatch" {
  name          = "alias/cloudwatch"
  target_key_id = aws_kms_key.cloudwatch.key_id
}

 resource "aws_cloudwatch_log_group" "good_example" {
 	name = "good_example"
 
 	kms_key_id = aws_kms_alias.cloudwatch.arn
 }
 `,
}

var terraformLogGroupCustomerKeyBadExamples = []string{
	`
 resource "aws_cloudwatch_log_group" "bad_example" {
 	name = "bad_example"
 
 }
 `,
}

var terraformLogGroupCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id`,
}

var terraformLogGroupCustomerKeyRemediationMarkdown = ``
