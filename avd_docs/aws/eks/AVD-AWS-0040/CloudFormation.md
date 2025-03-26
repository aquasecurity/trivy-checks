
Don't enable public access to EKS Clusters

```yaml
Resources:
  EKSCluster:
    Type: AWS::EKS::Cluster
    Properties:
      ResourcesVpcConfig:
        EndpointPublicAccess: fasle
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html

