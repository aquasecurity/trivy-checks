
Enable encryption using CMK

```yaml
Resources:
    GoodExample:
        Properties:
            Encrypted: true
            KmsKeyId: something
        Type: AWS::Redshift::Cluster
```


