provider "aws" {
  region = "us-west-1"
}

resource "aws_launch_template" "this" {
  name_prefix   = "test"
  image_id      = "ami-1a2b3c"
  instance_type = "t2.micro"
}

resource "aws_autoscaling_group" "this" {
  availability_zones = ["us-east-1a"]
  desired_capacity   = 20
  max_size           = 1
  min_size           = 1

  launch_template {
    id      = aws_launch_template.this.id
    version = "$Latest"
  }
}
