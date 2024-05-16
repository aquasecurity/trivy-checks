
Use a CMK for SNS Topic encryption

```yaml---
Resources:
  GoodTopic:
    Type: AWS::SQS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key

```


