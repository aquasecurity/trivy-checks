
Set the aggregator to cover all regions

```yaml
Resources:
  GoodExample:
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: true
      ConfigurationAggregatorName: GoodAccountLevelAggregation
    Type: AWS::Config::ConfigurationAggregator

```
```yaml
Resources:
  GoodExample:
    Properties:
      ConfigurationAggregatorName: GoodAccountLevelAggregation
      OrganizationAggregationSource:
        AllAwsRegions: true
    Type: AWS::Config::ConfigurationAggregator

```


