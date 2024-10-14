
Enable logging to CloudWatch

```yaml
Resources:
  GoodExampleTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*
      TrailName: Cloudtrail
```


