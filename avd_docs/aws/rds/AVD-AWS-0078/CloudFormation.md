
Use Customer Managed Keys to encrypt Performance Insights data

```yaml
Resources:
  GoodExample:
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: something
    Type: AWS::RDS::DBInstance

```


