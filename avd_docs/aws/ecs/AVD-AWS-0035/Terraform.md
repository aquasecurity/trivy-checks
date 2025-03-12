
Enable in transit encryption when using efs

```hcl
resource "aws_ecs_task_definition" "good_example" {
  container_definitions = file("task-definitions/service.json")
  volume {
    name = "service-storage"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.fs.id
      transit_encryption = "ENABLED"
    }
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption

