
Enable encryption using customer managed keys

```yaml
Resources:
  GoodCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      KmsKeyId: something
      StorageEncrypted: true
```


