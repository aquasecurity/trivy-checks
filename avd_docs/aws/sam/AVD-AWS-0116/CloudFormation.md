
Enable logging for API Gateway stages

```yaml
Resources:
    GoodExample:
        Properties:
            AccessLogSettings:
                DestinationArn: gateway-logging
                Format: json
            Name: Good SAM API example
            StageName: Prod
            Tracing: Activey
        Type: AWS::Serverless::HttpApi

```


