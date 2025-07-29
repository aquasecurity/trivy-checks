
Switch to HTTPS to benefit from TLS security features

```hcl
resource "aws_lb" "example" {}

resource "aws_alb_listener" "good_example" {
  load_balancer_arn = aws_lb.example.arn
  protocol          = "HTTPS"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener

