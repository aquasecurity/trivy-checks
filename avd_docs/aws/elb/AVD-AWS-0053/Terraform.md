
Switch to an internal load balancer or add a tfsec ignore

```hcl
resource "aws_alb" "good_example" {
  load_balancer_type = "gateway"
  internal           = false
}
```
```hcl
resource "aws_alb" "good_example" {
  internal = true
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb

