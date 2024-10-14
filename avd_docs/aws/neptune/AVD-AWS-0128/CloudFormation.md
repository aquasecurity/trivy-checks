
Enable encryption using customer managed keys

```yaml
Resources:
    GoodCluster:
        Properties:
            KmsKeyId: something
            StorageEncrypted: true
        Type: AWS::Neptune::DBCluster

```


