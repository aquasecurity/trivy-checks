
Enable at-rest encryption for replication group

```yaml
Resources:
  GoodExample:
    Type: AWS::ElastiCache::ReplicationGroup
    Properties:
      AtRestEncryptionEnabled: true
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html

