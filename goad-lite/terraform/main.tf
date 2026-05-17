# ─────────────────────────────────────────────────────────────
# WINDOWS SERVER 2019 AMI
# Canonical Windows AMI owned by Amazon
# ─────────────────────────────────────────────────────────────

data "aws_ami" "windows_2019" {
  most_recent = true
  owners      = ["801119661308"] # Amazon

  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ─────────────────────────────────────────────────────────────
# SECURITY GROUP — GOAD LITE WINDOWS VMs
# Kept here, separate from AegisAD security groups.
# Takes the scanner SG ID as input so the BloodHound scanner
# can reach the DC without the two stacks sharing .tf files.
# ─────────────────────────────────────────────────────────────

resource "aws_security_group" "goad_windows" {
  name        = "goad-lite-windows-sg"
  description = "GOAD Lite DC and member server"
  vpc_id      = var.aegisad_vpc_id

  # RDP — admin access only
  ingress {
    description = "RDP admin access"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.allowed_admin_ip]
  }

  # WinRM HTTP — Ansible uses this to configure AD
  ingress {
    description = "WinRM HTTP for Ansible"
    from_port   = 5985
    to_port     = 5985
    protocol    = "tcp"
    cidr_blocks = [var.allowed_admin_ip]
  }

  # WinRM HTTPS
  ingress {
    description = "WinRM HTTPS for Ansible"
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.allowed_admin_ip]
  }

  # All traffic from the AegisAD scanner so bloodhound-python can reach the DC
  ingress {
    description     = "All traffic from AegisAD scanner"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [var.aegisad_scanner_sg_id]
  }

  # Windows machines talking to each other (AD replication, domain join)
  ingress {
    description = "Inter-VM traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "goad-lite-windows-sg" }
}

# ─────────────────────────────────────────────────────────────
# DC01 — Domain Controller
# north.sevenkingdoms.local
# ─────────────────────────────────────────────────────────────

resource "aws_instance" "dc01" {
  ami                    = data.aws_ami.windows_2019.id
  instance_type          = "t3.medium" # AD needs more RAM than t3.micro
  subnet_id              = var.aegisad_subnet_id
  vpc_security_group_ids = [aws_security_group.goad_windows.id]
  key_name               = var.key_pair_name

  # Enables WinRM so Ansible can connect immediately after boot
  user_data = file("${path.module}/userdata/enable_winrm.ps1")

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "goad-lite-dc01"
    Role = "domain-controller"
  }
}

resource "aws_eip" "dc01" {
  instance = aws_instance.dc01.id
  domain   = "vpc"
  tags     = { Name = "goad-lite-dc01-eip" }
}

# ─────────────────────────────────────────────────────────────
# SRV01 — Member Server (joins the domain)
# ─────────────────────────────────────────────────────────────

resource "aws_instance" "srv01" {
  ami                    = data.aws_ami.windows_2019.id
  instance_type          = "t3.small"
  subnet_id              = var.aegisad_subnet_id
  vpc_security_group_ids = [aws_security_group.goad_windows.id]
  key_name               = var.key_pair_name

  user_data = file("${path.module}/userdata/enable_winrm.ps1")

  root_block_device {
    volume_size = 40
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "goad-lite-srv01"
    Role = "member-server"
  }
}

resource "aws_eip" "srv01" {
  instance = aws_instance.srv01.id
  domain   = "vpc"
  tags     = { Name = "goad-lite-srv01-eip" }
}
