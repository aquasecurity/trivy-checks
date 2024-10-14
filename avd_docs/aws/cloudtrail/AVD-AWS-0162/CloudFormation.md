
Enable logging to CloudWatch

```yaml
Resources:
    GoodExampleTrail:
        Properties:
            CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*
            TrailName: Cloudtrail
        Type: AWS::CloudTrail::Trail

```


