
Enable Container Insights

```yaml
Resources:
    GoodExample:
        Properties:
            ClusterName: MyCluster
            ClusterSettings:
                - Name: containerInsights
                  Value: enabled
        Type: AWS::ECS::Cluster

```


