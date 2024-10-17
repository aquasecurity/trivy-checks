
Enable encryption for EFS

```yaml
Resources:
  GoodExample:
    Type: AWS::EFS::FileSystem
    Properties:
      BackupPolicy:
        Status: ENABLED
      Encrypted: true
      LifecyclePolicies:
        - TransitionToIA: AFTER_60_DAYS
      PerformanceMode: generalPurpose
      ThroughputMode: bursting
```


