
Explicitly set the retention period to greater than the default

```yaml
Resources:
  GoodExample:
    Properties:
      BackupRetentionPeriod: 30
    Type: AWS::RDS::DBInstance

```


