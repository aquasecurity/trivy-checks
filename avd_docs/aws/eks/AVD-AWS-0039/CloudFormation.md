
Enable encryption of EKS secrets

```yaml
Resources:
  GoodExample:
    Type: AWS::EKS::Cluster
    Properties:
      EncryptionConfig:
        - Provider:
            KeyArn: alias/eks-kms
          Resources:
            - secrets
      Name: goodExample
      ResourcesVpcConfig:
        SecurityGroupIds:
          - sg-6979fe18
        SubnetIds:
          - subnet-6782e71e
          - subnet-e7e761ac
      RoleArn: arn:aws:iam::012345678910:role/eks-service-role-good-example
      Version: "1.14"
```


