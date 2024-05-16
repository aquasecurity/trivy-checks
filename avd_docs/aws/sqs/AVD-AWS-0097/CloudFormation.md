
Keep policy scope to the minimum that is required to be effective

```yaml---
Resources:
  GoodQueue:
    Type: AWS::SQS::Queue
    Properties:
      Name: something
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - Ref: MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "SQS:SendMessage" 
              - "SQS:ReceiveMessage"
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:  
              AWS: 
                - "111122223333"        

```


