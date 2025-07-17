
Enable at rest encryption

```yaml
Resources:
  GoodCluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionAtRest:
          DataVolumeKMSKeyId: foo-bar-key
```


