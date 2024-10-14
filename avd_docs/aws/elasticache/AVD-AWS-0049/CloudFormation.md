
Add descriptions for all security groups and rules

```yaml
Resources:
    GoodExampleCacheGroup:
        Properties:
            Description: Some description
        Type: AWS::ElastiCache::SecurityGroup
    GoodExampleEc2SecurityGroup:
        Properties:
            GroupDescription: Good Elasticache Security Group
            GroupName: GoodExample
        Type: AWS::EC2::SecurityGroup
    GoodSecurityGroupIngress:
        Properties:
            CacheSecurityGroupName: GoodExampleCacheGroup
            EC2SecurityGroupName: GoodExampleEc2SecurityGroup
        Type: AWS::ElastiCache::SecurityGroupIngress
```


