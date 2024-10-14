
Enable encryption for EFS

```yaml
Resources:
    GoodExample:
        Properties:
            BackupPolicy:
                Status: ENABLED
            Encrypted: true
            LifecyclePolicies:
                - TransitionToIA: AFTER_60_DAYS
            PerformanceMode: generalPurpose
            ThroughputMode: bursting
        Type: AWS::EFS::FileSystem
```


