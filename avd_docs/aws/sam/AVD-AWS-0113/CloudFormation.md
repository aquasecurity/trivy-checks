
Enable logging for API Gateway stages

```yaml
Resources:
    GoodExample:
        Properties:
            AccessLogSetting:
                DestinationArn: gateway-logging
                Format: json
            Domain:
                SecurityPolicy: TLS_1_2
            Name: Good SAM API example
            StageName: Prod
            TracingEnabled: false
        Type: AWS::Serverless::Api

```


