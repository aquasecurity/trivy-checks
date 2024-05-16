
Enable logging for API Gateway stages

```yaml---
Resources:
  GoodExample:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Activey
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json

```


