
Enable encryption of Neptune storage

```yaml---
Resources:
  GoodCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"

```


