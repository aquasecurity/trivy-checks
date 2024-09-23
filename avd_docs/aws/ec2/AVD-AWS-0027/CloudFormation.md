
Enable encryption using customer managed keys

```yaml---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot

```
```yaml---
Resources:
  MyKey:
    Type: 'AWS::KMS::Key'
    Properties:
      KeyPolicy:
        Version: 2012-10-17
        Id: key-default-1
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: !Ref MyKey 
    DeletionPolicy: Snapshot

```


