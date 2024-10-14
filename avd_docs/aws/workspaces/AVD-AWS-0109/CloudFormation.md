
Root and user volume encryption should be enabled

```yaml
Resources:
  GoodExample:
    Type: AWS::WorkSpaces::Workspace
    Properties:
      RootVolumeEncryptionEnabled: true
      UserName: admin
      UserVolumeEncryptionEnabled: true
```
```yaml
Resources:
  GoodExample:
    Type: AWS::WorkSpaces::Workspace
    Properties:
      RootVolumeEncryptionEnabled: true
      UserName: admin
      UserVolumeEncryptionEnabled: true
```


