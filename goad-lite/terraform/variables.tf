variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "dev"
}

# ── Passed in from AegisAD outputs ──────────────────────────────────────
# Run: terraform output -raw vpc_id  (in the aegisad/ directory)
# then paste the values into goad-lite/terraform/terraform.tfvars

variable "aegisad_vpc_id" {
  description = "VPC ID from AegisAD terraform output vpc_id"
  type        = string
}

variable "aegisad_subnet_id" {
  description = "Public subnet ID from AegisAD terraform output public_subnet_id"
  type        = string
}

variable "aegisad_scanner_sg_id" {
  description = "Scanner security group ID from AegisAD output scanner_security_group_id"
  type        = string
}

# ── GOAD Lite config ─────────────────────────────────────────────────────

variable "allowed_admin_ip" {
  description = "Your IP for RDP access (format: x.x.x.x/32)"
  type        = string
}

variable "key_pair_name" {
  description = "Existing EC2 key pair name for decrypting the Windows admin password"
  type        = string
}

variable "dc_domain" {
  description = "AD domain to create"
  type        = string
  default     = "north.sevenkingdoms.local"
}

variable "dc_netbios" {
  description = "NetBIOS name for the domain"
  type        = string
  default     = "NORTH"
}

variable "winrm_user" {
  description = "Local admin user Ansible uses for WinRM"
  type        = string
  default     = "Administrator"
}
