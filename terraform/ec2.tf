# ─────────────────────────────────────────
# GET THE LATEST UBUNTU 22.04 AMI
# Automatically finds the right AMI for
# whatever region you deploy in
# ─────────────────────────────────────────

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical (Ubuntu's official AWS account)

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ─────────────────────────────────────────
# SCANNER EC2 INSTANCE
# ─────────────────────────────────────────

resource "aws_instance" "scanner" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.scanner.id]
  iam_instance_profile   = aws_iam_instance_profile.scanner.name

  # user_data runs automatically when the instance
  # first boots — installs everything the scanner needs
  user_data = base64encode(templatefile(
    "${path.module}/userdata/scanner_setup.sh",
    {
      raw_bucket     = aws_s3_bucket.raw.bucket
      dynamodb_table = aws_dynamodb_table.scan_runs.id
      aws_region     = var.aws_region
      dc_domain      = var.dc_domain
    }
  ))

  root_block_device {
    volume_size = 20    # GB — enough for bloodhound output
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "${var.project_name}-scanner"
  }

  # Wait for instance to be fully running
  # before Terraform considers it done
  lifecycle {
    create_before_destroy = true
  }
}

# ─────────────────────────────────────────
# ELASTIC IP
# Gives the scanner a fixed public IP
# so SSM can always reach it
# ─────────────────────────────────────────

resource "aws_eip" "scanner" {
  instance = aws_instance.scanner.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-scanner-eip"
  }
}