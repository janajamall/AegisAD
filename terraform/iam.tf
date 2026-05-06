# ─────────────────────────────────────────
# TRIGGER LAMBDA ROLE
# ─────────────────────────────────────────

resource "aws_iam_role" "trigger_lambda" {
  name = "${var.project_name}-trigger-lambda-role"

  # Only Lambda functions can use this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "trigger_lambda" {
  name = "${var.project_name}-trigger-lambda-policy"
  role = aws_iam_role.trigger_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Write logs to CloudWatch (all Lambdas need this)
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        # Write and update rows in DynamoDB
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.scan_runs.arn
      },
      {
        # Send commands to EC2 via SSM
        Effect   = "Allow"
        Action   = ["ssm:SendCommand", "ssm:GetCommandInvocation"]
        Resource = "*"
      }
    ]
  })
}

# ─────────────────────────────────────────
# REPORT LAMBDA ROLE
# ─────────────────────────────────────────

resource "aws_iam_role" "report_lambda" {
  name = "${var.project_name}-report-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "report_lambda" {
  name = "${var.project_name}-report-lambda-policy"
  role = aws_iam_role.report_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Write logs to CloudWatch
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        # READ from the raw findings bucket only
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.raw.arn}/*"
      },
      {
        # WRITE to the reports bucket only
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.reports.arn}/*"
      },
      {
        # Update the scan status in DynamoDB
        Effect   = "Allow"
        Action   = ["dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.scan_runs.arn
      }
    ]
  })
}

# ─────────────────────────────────────────
# STATUS LAMBDA ROLE
# Only needs to read DynamoDB
# ─────────────────────────────────────────

resource "aws_iam_role" "status_lambda" {
  name = "${var.project_name}-status-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "status_lambda" {
  name = "${var.project_name}-status-lambda-policy"
  role = aws_iam_role.status_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        # Only needs to read the scan status
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = aws_dynamodb_table.scan_runs.arn
      }
    ]
  })
}

# ─────────────────────────────────────────
# DOWNLOAD LAMBDA ROLE
# Only needs to read S3 to sign presigned URLs
# ─────────────────────────────────────────

resource "aws_iam_role" "download_lambda" {
  name = "${var.project_name}-download-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "download_lambda" {
  name = "${var.project_name}-download-lambda-policy"
  role = aws_iam_role.download_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        # Only needs to read reports to sign presigned URLs
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.reports.arn}/*"
      }
    ]
  })
}
# ─────────────────────────────────────────
# SCANNER EC2 ROLE
# EC2 uses "instance profiles" not roles directly
# ─────────────────────────────────────────

resource "aws_iam_role" "scanner_ec2" {
  name = "${var.project_name}-scanner-ec2-role"

  # Only EC2 instances can use this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# This AWS-managed policy lets SSM control the EC2
# Without this, SSM Run Command cannot reach the instance
resource "aws_iam_role_policy_attachment" "scanner_ssm" {
  role       = aws_iam_role.scanner_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Allows the CloudWatch agent (installed by user_data) to push logs
resource "aws_iam_role_policy_attachment" "scanner_cloudwatch" {
  role       = aws_iam_role.scanner_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy" "scanner_ec2" {
  name = "${var.project_name}-scanner-ec2-policy"
  role = aws_iam_role.scanner_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Write findings zip + read config files (run.py) from raw bucket
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.raw.arn}/*"
      },
      {
        # Update scan status in DynamoDB
        Effect   = "Allow"
        Action   = ["dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.scan_runs.arn
      },
      {
        # Write logs to CloudWatch
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}

# EC2 needs an "instance profile" to wear an IAM role
# Think of it as the physical badge holder
resource "aws_iam_instance_profile" "scanner" {
  name = "${var.project_name}-scanner-instance-profile"
  role = aws_iam_role.scanner_ec2.name
}