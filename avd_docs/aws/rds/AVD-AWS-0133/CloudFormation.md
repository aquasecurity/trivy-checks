
Enable performance insights

```yaml---
Resources:
  GoodExample:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"


```


