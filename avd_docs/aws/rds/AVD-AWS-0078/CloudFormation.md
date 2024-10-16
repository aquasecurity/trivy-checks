
Use Customer Managed Keys to encrypt Performance Insights data

```yaml
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: something
```


