
Do not allow public access in the policy

```yaml
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: test-repository
      RepositoryPolicyText:
        Statement:
          - Action:
              - ecr:PutImage
            Effect: Allow
            Principal:
              AWS:
                - arn:aws:iam::123456789012:user/Alice
            Sid: AllowPushPull
        Version: "2012-10-17"
```


