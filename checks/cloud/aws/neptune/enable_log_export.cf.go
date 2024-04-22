package neptune

var cloudFormationEnableLogExportGoodExamples = []string{
	`---
Resources:
  GoodCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - audit
`,
}

var cloudFormationEnableLogExportBadExamples = []string{
	`---
Resources:
  BadCluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - debug
`,
}

var cloudFormationEnableLogExportLinks = []string{}

var cloudFormationEnableLogExportRemediationMarkdown = ``
