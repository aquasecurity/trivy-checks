
Configure snapshot retention for redis cluster

```hcl
resource "aws_elasticache_cluster" "good_example" {
  engine                   = "redis"
  node_type                = "cache.m4.large"
  snapshot_retention_limit = 5
}
```
```hcl
resource "aws_elasticache_cluster" "good_example" {
  engine    = "memcached"
  node_type = "cache.m4.large"
}
```
```hcl
resource "aws_elasticache_cluster" "good_example" {
  engine    = "redis"
  node_type = "cache.t1.micro"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit

