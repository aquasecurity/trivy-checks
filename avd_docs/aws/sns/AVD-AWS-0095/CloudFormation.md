
Turn on SNS Topic encryption

```yaml
Resources:
  GoodTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: some-key
      TopicName: blah
```


