# Example Terraform — intentionally has security & cost issues for demo

resource "aws_s3_bucket" "assets" {
  bucket = "my-company-assets"
  acl    = "public-read"
}

resource "aws_db_instance" "primary" {
  identifier        = "prod-db"
  instance_class    = "db.r5.2xlarge"
  engine            = "postgres"
  storage_encrypted = false
}

resource "aws_instance" "app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "m5.xlarge"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
