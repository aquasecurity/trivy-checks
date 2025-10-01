resource "aws_s3_bucket" "this" {
  bucket = "test"
  tags = {
    Owner: "user"
  }
}
