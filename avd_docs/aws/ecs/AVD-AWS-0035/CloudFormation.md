
Enable in transit encryption when using efs

```yaml
Resources:
  GoodExample:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Image: amazon/amazon-ecs-sample
      Volumes:
        - EFSVolumeConfiguration:
            FilesystemId: fs1
            TransitEncryption: ENABLED
          Name: jenkins-home
```


