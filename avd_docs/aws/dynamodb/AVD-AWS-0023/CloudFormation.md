
Enable encryption at rest for DAX Cluster

```yaml
Resources:
    GoodExample:
        Properties:
            ClusterName: MyDAXCluster
            Description: DAX cluster with encryption at rest
            IAMRoleARN: arn:aws:iam::111122223333:role/DaxAccess
            NodeType: dax.r3.large
            ReplicationFactor: 1
            SSESpecification:
                SSEEnabled: true
        Type: AWS::DAX::Cluster
```


