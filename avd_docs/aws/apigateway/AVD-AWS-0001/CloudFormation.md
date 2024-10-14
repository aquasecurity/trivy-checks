
Enable logging for API Gateway stages

```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Description: Good Example of ApiGateway
Resources:
    GoodApi:
        Type: AWS::ApiGatewayV2::Api
    GoodApiStage:
        Properties:
            AccessLogSettings:
                DestinationArn: gateway-logging
                Format: json
            ApiId: GoodApi
            StageName: GoodApiStage
        Type: AWS::ApiGatewayV2::Stage
```


