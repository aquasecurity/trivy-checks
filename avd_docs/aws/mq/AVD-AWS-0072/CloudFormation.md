
Disable public access when not required

```yaml
Resources:
    GoodBroker:
        Properties:
            PubliclyAccessible: false
        Type: AWS::AmazonMQ::Broker
```


