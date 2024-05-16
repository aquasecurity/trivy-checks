
Turn on SQS Queue encryption

```yaml---
Resources:
  GoodQueue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue

```


