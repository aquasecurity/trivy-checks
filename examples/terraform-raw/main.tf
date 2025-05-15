resource "aws_s3_bucket" "test" {
  bucket = "test"
  tags = {
    Environment = "Production"
    Project     = "ProjectX"
  }
}
