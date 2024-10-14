
Enable encryption of EBS volumes

```yaml
Resources:
    GoodExample:
        DeletionPolicy: Snapshot
        Properties:
            Encrypted: true
            KmsKeyId: alias/volumeEncrypt
            Size: 100
        Type: AWS::EC2::Volume

```


