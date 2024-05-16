
Enable tracing

```yaml---
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: true

```


