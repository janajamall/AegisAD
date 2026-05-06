output "vpc_id" {
  description = "VPC ID — needed if adding more resources later"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "Subnet ID — use this when launching EC2 instances"
  value       = aws_subnet.public.id
}

output "scanner_security_group_id" {
  description = "Attach this SG to the Linux scanner EC2"
  value       = aws_security_group.scanner.id
}

output "windows_security_group_id" {
  description = "Attach this SG to the Windows DC and workstation"
  value       = aws_security_group.windows.id
}

output "raw_bucket_name" {
  description = "Scanner uploads findings.zip here"
  value       = aws_s3_bucket.raw.bucket
}

output "reports_bucket_name" {
  description = "Report Lambda uploads PDFs here"
  value       = aws_s3_bucket.reports.bucket
}

output "dashboard_bucket_name" {
  description = "Upload index.html here to deploy the dashboard"
  value       = aws_s3_bucket.dashboard.bucket
}

output "dashboard_url" {
  description = "Open this URL in a browser to see the dashboard"
  value       = "http://${aws_s3_bucket_website_configuration.dashboard.website_endpoint}"
}

output "dynamodb_table_name" {
  description = "All Lambdas read and write to this table"
  value       = aws_dynamodb_table.scan_runs.id
}

output "scanner_instance_profile_name" {
  description = "Attach this to the Linux scanner EC2 when launching"
  value       = aws_iam_instance_profile.scanner.name
}

output "trigger_lambda_role_arn" {
  description = "Use this role ARN when creating the Trigger Lambda"
  value       = aws_iam_role.trigger_lambda.arn
}

output "report_lambda_role_arn" {
  description = "Use this role ARN when creating the Report Lambda"
  value       = aws_iam_role.report_lambda.arn
}

output "status_lambda_role_arn" {
  description = "Use this role ARN when creating the Status Lambda"
  value       = aws_iam_role.status_lambda.arn
}

output "download_lambda_role_arn" {
  description = "Use this role ARN when creating the Download Lambda"
  value       = aws_iam_role.download_lambda.arn
}
output "api_url" {
  description = "Base URL for all API calls — put this in the dashboard"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "scan_endpoint" {
  description = "POST to this URL to start a scan"
  value       = "${aws_apigatewayv2_stage.default.invoke_url}/scan"
}
output "scanner_instance_id" {
  description = "Put this in variables.tf as scanner_instance_id"
  value       = aws_instance.scanner.id
}

output "scanner_public_ip" {
  description = "Scanner EC2 public IP — for SSH if needed"
  value       = aws_eip.scanner.public_ip
}