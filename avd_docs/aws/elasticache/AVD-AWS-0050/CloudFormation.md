
Configure snapshot retention for redis cluster

```yaml
Resources:
    GoodExample:
        Properties:
            AZMode: cross-az
            CacheNodeType: cache.m3.medium
            Engine: redis
            NumCacheNodes: "3"
            PreferredAvailabilityZones:
                - us-west-2a
                - us-west-2a
                - us-west-2b
            SnapshotRetentionLimit: 7
        Type: AWS::ElastiCache::CacheCluster

```


