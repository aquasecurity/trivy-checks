
Disable public access when not required

```yaml
Resources:
  GoodBroker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: false
```


