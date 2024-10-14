
Keep policy scope to the minimum that is required to be effective

```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Description: Good example of queue policy
Resources:
    MyQueue:
        Properties:
            Name: something
        Type: AWS::SQS::Queue
    SampleSQSPolicy:
        Properties:
            PolicyDocument:
                Statement:
                    - Action:
                        - SQS:SendMessage
                        - SQS:ReceiveMessage
                      Effect: Allow
                      Principal:
                        AWS:
                            - "111122223333"
                      Resource: arn:aws:sqs:us-east-2:444455556666:queue2
            Queues:
                - Ref: MyQueue
        Type: AWS::SQS::QueuePolicy
```


