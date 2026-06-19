
Enable logging for CloudFront distributions

```yaml
Resources:
  GoodExample:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
```
```yaml
Resources:
  GoodDistV2:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          ViewerProtocolPolicy: redirect-to-https
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.2_2021

  DeliverySource:
    Type: AWS::Logs::DeliverySource
    Properties:
      LogType: ACCESS_LOGS
      Name: cloudfront-log-delivery-source
      ResourceArn: !Ref GoodDistV2

  Delivery:
    Type: AWS::Logs::Delivery
    Properties:
      DeliverySourceName: !Ref DeliverySource
```


