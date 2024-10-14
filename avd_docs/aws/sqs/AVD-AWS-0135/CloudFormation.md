
Encrypt SQS Queue with a customer-managed key

```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Description: Good example of queue
Resources:
    Queue:
        Properties:
            KmsMasterKeyId: some-key
            QueueName: my-queue
        Type: AWS::SQS::Queue

```


