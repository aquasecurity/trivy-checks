
Enable general logging

```yaml
Resources:
  GoodBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        General: true
```


