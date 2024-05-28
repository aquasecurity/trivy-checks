
Encrypt SQS Queue with a customer-managed key

```yaml---
Resources:
  GoodQueue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue

```


