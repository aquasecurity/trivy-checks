
Enable in transit encryption for replication group

```yaml
Resources:
  GoodExample:
    Properties:
      AutomaticFailoverEnabled: true
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: CacheSubnetGroup
      Engine: redis
      EngineVersion: "3.2"
      NumNodeGroups: "2"
      Port: 6379
      PreferredMaintenanceWindow: sun:05:00-sun:09:00
      ReplicasPerNodeGroup: "3"
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
        - ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: 10:00-12:00
      TransitEncryptionEnabled: true
    Type: AWS::ElastiCache::ReplicationGroup

```


