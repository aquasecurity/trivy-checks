
Deploy Redshift cluster into a non default VPC

```yaml
Resources:
  GoodCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: my-subnet-group
```


