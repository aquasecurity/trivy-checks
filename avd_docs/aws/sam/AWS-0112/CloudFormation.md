
Use the most modern TLS/SSL policies available

```yaml
Resources:
  GoodExample:
    Type: AWS::Serverless::Api
    Properties:
      Domain:
        SecurityPolicy: TLS_1_2
      Name: Good SAM API example (legacy TLS 1.2)
      StageName: Prod
      TracingEnabled: false
```
```yaml
Resources:
  GoodExampleTLS13:
    Type: AWS::Serverless::Api
    Properties:
      Domain:
        SecurityPolicy: SecurityPolicy_TLS13_1_2_2021_06
      Name: Good SAM API example (TLS 1.3)
      StageName: Prod
      TracingEnabled: false
```


