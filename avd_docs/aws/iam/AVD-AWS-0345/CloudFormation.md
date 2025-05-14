
Create more restrictive S3 policies

```yaml
AWSTemplateFormatVersion: "2010-09-09"

Resources:
  GoodPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: good_policy
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
              - s3:PutObject
            Resource: arn:aws:s3:::examplebucket/*
      Roles:
        - !Ref GoodRole

  GoodRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: good_role
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
```


