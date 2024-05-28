
Enable encryption for RDS instances

```yaml---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"


```


