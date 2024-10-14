
Use a CMK for SNS Topic encryption

```yaml
Resources:
    GoodTopic:
        Properties:
            KmsMasterKeyId: some-key
            TopicName: blah
        Type: AWS::SQS::Topic
```


