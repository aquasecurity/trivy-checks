
Enable export logs

```yaml
Resources:
  GoodCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - audit
```


