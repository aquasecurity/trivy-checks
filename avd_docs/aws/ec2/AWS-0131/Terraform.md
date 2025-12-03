
Turn on encryption for all block devices

```hcl
resource "aws_instance" "good_example" {
  ami           = "ami-7f89a64f"
  instance_type = "t1.micro"

  root_block_device {
    encrypted = true
  }

  ebs_block_device {
    device_name = "/dev/sdg"
    encrypted   = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices

