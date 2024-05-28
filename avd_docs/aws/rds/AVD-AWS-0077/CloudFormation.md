
Explicitly set the retention period to greater than the default

```yaml---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      BackupRetentionPeriod: 30

```


