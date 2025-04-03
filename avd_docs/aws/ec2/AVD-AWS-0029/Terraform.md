
Remove sensitive data from the EC2 instance user-data

```hcl
resource "aws_instance" "good_example" {
  ami           = "ami-12345667"
  instance_type = "t2.small"

  user_data = <<EOF
	 export GREETING=hello
 EOF
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data

