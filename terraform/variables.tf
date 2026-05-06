variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for all resource names"
  type        = string
  default     = "aegisad"
}

variable "environment" {
  description = "Environment label"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}
// ip addresses for the vpc
variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}
// ip for the subnet and instances
variable "allowed_admin_ip" {
  description = "Your IP address for RDP and SSH access"
  type        = string
  default     = "0.0.0.0/0"
}
variable "dc_domain" {
  description = "Active Directory domain name (e.g. north.sevenkingdoms.local)"
  type        = string
  default     = "north.sevenkingdoms.local"
}
variable "scanner_instance_id" {
  description = "EC2 instance ID of the Linux scanner"
  type        = string
  default     = "i-047eb84a2c668745e"
}