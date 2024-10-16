
Enable logging for API Gateway stages

```yaml
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json
      Domain:
        SecurityPolicy: TLS_1_2
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: false
```


