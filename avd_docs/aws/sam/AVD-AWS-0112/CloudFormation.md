
Use the most modern TLS/SSL policies available

```yaml
Resources:
    GoodExample:
        Properties:
            Domain:
                SecurityPolicy: TLS_1_2
            Name: Good SAM API example
            StageName: Prod
            TracingEnabled: false
        Type: AWS::Serverless::Api

```


