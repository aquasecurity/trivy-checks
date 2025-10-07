
Use the most modern TLS/SSL policies available

```yaml
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      Domain:
        SecurityPolicy: TLS_1_2
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: false
```


