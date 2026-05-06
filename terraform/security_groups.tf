# Firewall for the Linux scanner EC2
resource "aws_security_group" "scanner" {
  name        = "${var.project_name}-scanner-sg"
  description = "Security group for the BloodHound scanner EC2"
  vpc_id      = aws_vpc.main.id

  # SSH from anywhere for emergency access
  # In production this would be locked to one IP
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_admin_ip]
  }

  # Allow everything outbound
  # Scanner needs to reach: DC (LDAP), S3, DynamoDB, SSM
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-scanner-sg"
  }
}

# Firewall for the Windows DC and workstation
resource "aws_security_group" "windows" {
  name        = "${var.project_name}-windows-sg"
  description = "Security group for the Windows DC and workstation"
  vpc_id      = aws_vpc.main.id

  # RDP from allowed IP only (for setup and admin)
  ingress {
    description = "RDP access"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.allowed_admin_ip]
  }

  # All traffic from the Linux scanner
  # This is how bloodhound-python reaches the DC over LDAP
  ingress {
    description     = "All traffic from scanner"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.scanner.id]
  }

  # Windows machines talking to each other
  # Required for domain join and AD replication
  ingress {
    description = "Windows to Windows traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  # Allow everything outbound
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-windows-sg"
  }
}