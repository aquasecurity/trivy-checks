
Enable audit logging

```yaml
Resources:
  GoodBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        Audit: true
```


