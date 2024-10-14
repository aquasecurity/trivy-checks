
Enable cache encryption

```yaml
Resources:
    GoodExample:
        Properties:
            Domain:
                SecurityPolicy: TLS_1_2
            MethodSettings:
                CacheDataEncrypted: true
            Name: Good SAM API example
            StageName: Prod
            TracingEnabled: false
        Type: AWS::Serverless::Api

```


