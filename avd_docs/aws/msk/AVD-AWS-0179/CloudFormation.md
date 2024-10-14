
Enable at rest encryption

```yaml
Resources:
    GoodCluster:
        Properties:
            EncryptionInfo:
                EncryptionAtRest:
                    DataVolumeKMSKeyId: foo-bar-key
        Type: AWS::MSK::Cluster

```


