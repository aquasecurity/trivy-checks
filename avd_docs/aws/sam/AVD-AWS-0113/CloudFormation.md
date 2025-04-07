
Enable logging for API Gateway stages

```yaml
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json
      Name: Good SAM API example
      StageName: Prod
```


