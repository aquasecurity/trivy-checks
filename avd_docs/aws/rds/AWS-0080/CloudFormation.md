
Enable encryption for RDS instances

```yaml
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      KmsKeyId: something
      StorageEncrypted: true
```


