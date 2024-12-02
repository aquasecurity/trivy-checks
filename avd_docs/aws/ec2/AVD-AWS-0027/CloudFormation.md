
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
  MyKey:
    Type: AWS::KMS::Key
    Properties:
      KeyPolicy:
        Version: "2012-10-17"
        Id: key-default-1

  GoodExample:
    DeletionPolicy: Snapshot
    Type: AWS::EC2::Volume
    Properties:
      Encrypted: true
      KmsKeyId: !Ref MyKey
      Size: 100
```


