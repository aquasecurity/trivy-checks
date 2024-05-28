
Enable logging for API Gateway stages

```yaml---
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: false
      Domain:
        SecurityPolicy: TLS_1_2
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json

```


