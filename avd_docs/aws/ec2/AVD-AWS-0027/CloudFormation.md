
Enable encryption using customer managed keys

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
```yaml
Resources:
    GoodExample:
        DeletionPolicy: Snapshot
        Properties:
            Encrypted: true
            KmsKeyId: MyStack:Key
            Size: 100
        Type: AWS::EC2::Volume

```


