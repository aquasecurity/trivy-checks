
Enable audit logging

```yaml
Resources:
    GoodBroker:
        Properties:
            Logs:
                Audit: true
        Type: AWS::AmazonMQ::Broker

```


