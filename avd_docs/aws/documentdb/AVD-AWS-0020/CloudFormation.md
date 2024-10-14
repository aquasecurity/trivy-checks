
Enable export logs

```yaml
Resources:
    GoodExample:
        Properties:
            BackupRetentionPeriod: 8
            DBClusterIdentifier: sample-cluster
            DBClusterParameterGroupName: default.docdb3.6
            EnableCloudwatchLogsExports:
                - audit
                - profiler
            KmsKeyId: your-kms-key-id
        Type: AWS::DocDB::DBCluster
    InstanceInstanceExample:
        Properties:
            AutoMinorVersionUpgrade: true
            AvailabilityZone: us-east-1c
            DBClusterIdentifier: sample-cluster
            DBInstanceClass: db.r5.large
            DBInstanceIdentifier: sample-cluster-instance-0
            PreferredMaintenanceWindow: sat:06:54-sat:07:24
        Type: AWS::DocDB::DBInstance

```


