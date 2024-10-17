
Turn on SNS Topic encryption

```yaml
Resources:
  GoodTopic:
    Type: AWS::SQS::Topic
    Properties:
      KmsMasterKeyId: some-key
      TopicName: blah
```


