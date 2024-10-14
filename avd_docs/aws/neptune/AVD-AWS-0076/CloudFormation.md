
Enable encryption of Neptune storage

```yaml
Resources:
    GoodCluster:
        Properties:
            KmsKeyId: something
            StorageEncrypted: true
        Type: AWS::Neptune::DBCluster

```


