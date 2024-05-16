package sam

var cloudFormationEnableFunctionTracingGoodExamples = []string{
	`---
Resources:
  GoodFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
      Tracing: Active
`,
}

var cloudFormationEnableFunctionTracingBadExamples = []string{
	`---
Resources:
  BadFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
`,
}

var cloudFormationEnableFunctionTracingLinks = []string{}

var cloudFormationEnableFunctionTracingRemediationMarkdown = ``
