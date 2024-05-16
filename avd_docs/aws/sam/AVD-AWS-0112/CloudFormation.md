
Use the most modern TLS/SSL policies available

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

```


