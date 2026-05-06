resource "aws_dynamodb_table" "scan_runs" {
  # Table name
  name = "${var.project_name}-scan-runs"

  # PAY_PER_REQUEST means you only pay when
  # the table is actually used. Zero cost when idle.
  # Perfect for a student project.
  billing_mode = "PAY_PER_REQUEST"

  # The primary key — every row must have a unique run_id
  hash_key = "run_id"

  attribute {
    name = "run_id"
    type = "S" # S means String
  }

  # Encrypt everything stored in the table
  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-scan-runs"
  }
}