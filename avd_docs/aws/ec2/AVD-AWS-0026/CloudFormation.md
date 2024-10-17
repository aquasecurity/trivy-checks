
Enable encryption of EBS volumes

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


