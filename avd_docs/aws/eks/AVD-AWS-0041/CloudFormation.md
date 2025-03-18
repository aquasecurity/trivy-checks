
Don't enable public access to EKS Clusters

```yaml
Resources:
  EKSCluster:
    Type: AWS::EKS::Cluster
    Properties:
      ResourcesVpcConfig:
        EndpointPublicAccess: false
        PublicAccessCidrs:
          - 10.2.0.0/8
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html

