
Enable encryption using customer managed keys

```yaml
Resources:
  GoodExample:
    DeletionPolicy: Snapshot
    Type: AWS::EC2::Volume
    Properties:
      Encrypted: true
      KmsKeyId: alias/volumeEncrypt
      Size: 100
```
```yaml
Resources:
  GoodExample:
    DeletionPolicy: Snapshot
    Type: AWS::EC2::Volume
    Properties:
      Encrypted: true
      KmsKeyId: MyStack:Key
      Size: 100
```


