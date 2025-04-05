
Enable logging for the EKS control plane

```hcl
resource "aws_eks_cluster" "good_example" {
  enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types

