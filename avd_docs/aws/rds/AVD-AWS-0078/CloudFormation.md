
Use Customer Managed Keys to encrypt Performance Insights data

```yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"


```


