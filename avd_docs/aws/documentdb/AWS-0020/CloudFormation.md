
Enable export logs

```yaml
Resources:
  GoodExample:
    Type: AWS::DocDB::DBCluster
    Properties:
      DBClusterIdentifier: sample-cluster
      DBClusterParameterGroupName: default.docdb3.6
      EnableCloudwatchLogsExports:
        - audit
        - profiler

  InstanceInstanceExample:
    Type: AWS::DocDB::DBInstance
    Properties:
      DBClusterIdentifier: sample-cluster
      DBInstanceClass: db.r5.large
      DBInstanceIdentifier: sample-cluster-instance-0
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html

