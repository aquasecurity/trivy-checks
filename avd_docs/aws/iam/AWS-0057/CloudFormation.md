
Specify the exact permissions required, and to which resources they should apply instead of using wildcards.

```yaml
Resources:
  GoodPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: CFNUsers
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - s3:ListBuckets
            Resource: specific-bucket
```


