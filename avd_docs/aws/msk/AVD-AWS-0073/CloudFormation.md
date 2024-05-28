
Enable in transit encryption

```yaml---
Resources:
  GoodCluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS"

```


