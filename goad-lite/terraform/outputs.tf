output "dc01_public_ip" {
  description = "DC01 public IP — use this as DC_IP in the AegisAD scanner credentials.env"
  value       = aws_eip.dc01.public_ip
}

output "dc01_private_ip" {
  description = "DC01 private IP — use this for intra-VPC scanner traffic (preferred)"
  value       = aws_instance.dc01.private_ip
}

output "srv01_public_ip" {
  value = aws_eip.srv01.public_ip
}

output "srv01_private_ip" {
  value = aws_instance.srv01.private_ip
}

output "ansible_inventory_hint" {
  description = "Copy these IPs into goad-lite/ansible/inventory.yml"
  value = {
    dc01 = aws_eip.dc01.public_ip
    srv01 = aws_eip.srv01.public_ip
  }
}
