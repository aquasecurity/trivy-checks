
Enable encryption for RDS instances

```yaml
Resources:
    GoodExample:
        Properties:
            KmsKeyId: something
            StorageEncrypted: true
        Type: AWS::RDS::DBInstance

```


