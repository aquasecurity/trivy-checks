
Enable export logs

```yaml
Resources:
  GoodCluster:
    Properties:
      EnableCloudwatchLogsExports:
        - audit
    Type: AWS::Neptune::DBCluster

```


