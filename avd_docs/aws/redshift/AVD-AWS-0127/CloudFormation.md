
Deploy Redshift cluster into a non default VPC

```yaml
Resources:
    GoodCluster:
        Properties:
            ClusterSubnetGroupName: my-subnet-group
        Type: AWS::Redshift::Cluster
```


