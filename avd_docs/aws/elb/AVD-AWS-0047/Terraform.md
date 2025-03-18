
Use a more recent TLS/SSL policy for the load balancer

```hcl
resource "aws_lb" "example" {}

resource "aws_alb_listener" "good_example" {
  load_balancer_arn = aws_lb.example.arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  protocol          = "HTTPS"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener

