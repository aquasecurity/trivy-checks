
Use the most modern TLS/SSL policies available

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
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.2_2025
```


