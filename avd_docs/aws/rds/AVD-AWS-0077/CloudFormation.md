
Explicitly set the retention period to greater than the default

```yaml---
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      BackupRetentionPeriod: 30


```


