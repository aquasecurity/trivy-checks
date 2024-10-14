
Enable CMK encryption of CloudWatch Log Groups

```yaml
Resources:
    GoodExample:
        Properties:
            KmsKeyId: arn:aws:kms:us-west-2:111122223333:key/lambdalogging
            LogGroupName: aws/lambda/goodExample
            RetentionInDays: 30
        Type: AWS::Logs::LogGroup
```


