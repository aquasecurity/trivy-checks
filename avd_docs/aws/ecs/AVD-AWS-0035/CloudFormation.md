
Enable in transit encryption when using efs

```yaml
Resources:
  GoodExample:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled

  GoodTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Image: cfsec/cfsec:latest
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: cfsec-logs
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: cfsec
          MountPoints:
            - ContainerPath: /src
              SourceVolume: src
          Name: cfsec
      Cpu: 512
      Family: CFSec scan
      Memory: 1024
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
        - EC2
      Volumes:
        - EFSVolumeConfiguration:
            FilesystemId: fs1
            TransitEncryption: ENABLED
          Name: jenkins-home
```


