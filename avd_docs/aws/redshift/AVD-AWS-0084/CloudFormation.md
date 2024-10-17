
Enable encryption using CMK

```yaml
Resources:
  GoodExample:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true
      KmsKeyId: something
```


