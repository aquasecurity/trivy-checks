
Enable logging

```yaml
Resources:
    GoodCluster:
        Properties:
            LoggingInfo:
                BrokerLogs:
                    S3:
                        Enabled: true
        Type: AWS::MSK::Cluster

```


