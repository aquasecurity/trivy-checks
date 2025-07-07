
Use secrets for the task definition

```yaml
Resources:
  GoodExample:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - Image: amazon/amazon-ecs-sample
```


