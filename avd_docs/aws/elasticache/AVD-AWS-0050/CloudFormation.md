
Configure snapshot retention for redis cluster

```yaml
Resources:
  GoodExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      CacheNodeType: cache.m3.medium
      Engine: redis
      SnapshotRetentionLimit: 7
```
```yaml
Resources:
  GoodExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      Engine: redis
      CacheNodeType: cache.t1.micro
```
```yaml
Resources:
  GoodExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      Engine: memcached
```


