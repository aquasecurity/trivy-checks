
Enable in transit encryption

```yaml
Resources:
  GoodCluster:
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: TLS
    Type: AWS::MSK::Cluster

```


