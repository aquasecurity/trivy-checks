
Enable encryption for RDS clusters

```yaml
Resources:
    GoodExample:
        Properties:
            KmsKeyId: something
            StorageEncrypted: true
        Type: AWS::RDS::DBCluster
```


