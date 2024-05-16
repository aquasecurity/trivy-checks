
Enable encryption at rest for DAX Cluster

```yaml---
Resources:
  GoodExample:
    Type: AWS::DAX::Cluster
    Properties:
      ClusterName: "MyDAXCluster"
      NodeType: "dax.r3.large"
      ReplicationFactor: 1
      IAMRoleARN: "arn:aws:iam::111122223333:role/DaxAccess"
      Description: "DAX cluster with encryption at rest"
      SSESpecification:
        SSEEnabled: true

```


