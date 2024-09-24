package ec2

var terraformNoDefaultVpcGoodExamples = []string{
	`
 # no aws default vpc present
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
 `,
}

var terraformNoDefaultVpcBadExamples = []string{
	`
 resource "aws_default_vpc" "default" {
 	tags = {
 	  Name = "Default VPC"
 	}
   }
 `,
}

var terraformNoDefaultVpcLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc`,
}

var terraformNoDefaultVpcRemediationMarkdown = ``
