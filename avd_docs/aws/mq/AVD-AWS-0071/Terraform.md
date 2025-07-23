
Enable general logging

```hcl
resource "aws_mq_broker" "good_example" {
  broker_name        = "example"
  engine_type        = "ActiveMQ"
  engine_version     = "5.15.0"
  host_instance_type = "mq.t2.micro"
  user {
    username = "ExampleUser"
    password = "MindTheGap"
  }
  logs {
    general = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker#general

