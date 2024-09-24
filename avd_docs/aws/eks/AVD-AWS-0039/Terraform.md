
Enable encryption of EKS secrets

```hcl
resource "aws_kms_key" "eks" {
	enable_key_rotation = true
}

 resource "aws_eks_cluster" "good_example" {
     encryption_config {
         resources = [ "secrets" ]
         provider {
             key_arn = aws_kms_key.eks.arn
         }
     }
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config

