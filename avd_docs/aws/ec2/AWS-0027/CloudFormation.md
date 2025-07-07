
Enable encryption using customer managed keys

```yaml
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties:
      KmsKeyId: alias/volumeEncrypt
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
    Type: AWS::EC2::Volume
    Properties:
      KmsKeyId: !Ref MyKey
```


