
Enable logging

```yaml
Resources:
  GoodExample:
    Type: AWS::AWS::Serverless::StateMachine
    Properties:
      Logging:
        Level: ALL
        Destinations:
          - CloudWatchLogsLogGroup:
              LogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/states/my-logs:*
```


