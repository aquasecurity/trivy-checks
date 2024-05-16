
Enable encryption for RDS clusters

```yaml---
Resources:
  GoodExample:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"

```


