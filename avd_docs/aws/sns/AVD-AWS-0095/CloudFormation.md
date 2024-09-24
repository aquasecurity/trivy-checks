
Turn on SNS Topic encryption

```yaml---
Resources:
  GoodTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key

```


