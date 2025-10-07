
Don't enable public access to EKS Clusters

```hcl
resource "aws_eks_cluster" "good_example" {
  name = "good_example_cluster"
  vpc_config {
    endpoint_public_access = false
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_public_access

