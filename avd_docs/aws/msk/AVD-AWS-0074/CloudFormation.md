
Enable logging

```yaml---
Resources:
  GoodCluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          S3:
            Enabled: true



```


