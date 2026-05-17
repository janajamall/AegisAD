# ─────────────────────────────────────────
# ZIP THE LAMBDA CODE AUTOMATICALLY
# Terraform reads the Python files and zips them
# ─────────────────────────────────────────

data "archive_file" "trigger" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/trigger/handler.py"
  output_path = "${path.module}/../lambdas/trigger/trigger.zip"
}

data "archive_file" "status" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/status/handler.py"
  output_path = "${path.module}/../lambdas/status/status.zip"
}

data "archive_file" "download" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/download/handler.py"
  output_path = "${path.module}/../lambdas/download/download.zip"
}

data "archive_file" "report" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/report/"
  output_path = "${path.module}/report.zip"
  excludes    = [".gitkeep"]
}

# ─────────────────────────────────────────
# TRIGGER LAMBDA
# ─────────────────────────────────────────

resource "aws_lambda_function" "trigger" {
  function_name    = "${var.project_name}-trigger"
  role             = aws_iam_role.trigger_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.trigger.output_path
  source_code_hash = data.archive_file.trigger.output_base64sha256
  timeout          = 30
  memory_size      = 256

  # Environment variables the Lambda code reads with os.environ
  environment {
    variables = {
      DYNAMODB_TABLE      = aws_dynamodb_table.scan_runs.id
      SCANNER_INSTANCE_ID = aws_instance.scanner.id
    }
  }

  tags = {
    Name = "${var.project_name}-trigger"
  }
}

# ─────────────────────────────────────────
# STATUS LAMBDA
# ─────────────────────────────────────────

resource "aws_lambda_function" "status" {
  function_name    = "${var.project_name}-status"
  role             = aws_iam_role.status_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.status.output_path
  source_code_hash = data.archive_file.status.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.scan_runs.id
    }
  }

  tags = {
    Name = "${var.project_name}-status"
  }
}

# ─────────────────────────────────────────
# DOWNLOAD LAMBDA
# ─────────────────────────────────────────

resource "aws_lambda_function" "download" {
  function_name    = "${var.project_name}-download"
  role             = aws_iam_role.download_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.download.output_path
  source_code_hash = data.archive_file.download.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      REPORTS_BUCKET = aws_s3_bucket.reports.bucket
    }
  }

  tags = {
    Name = "${var.project_name}-download"
  }
}

# ─────────────────────────────────────────
# REPORT LAMBDA
# Needs more memory and time — generates PDFs
# ─────────────────────────────────────────

resource "aws_lambda_function" "report" {
  function_name    = "${var.project_name}-report"
  role             = aws_iam_role.report_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.report.output_path
  source_code_hash = data.archive_file.report.output_base64sha256
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      RAW_BUCKET     = aws_s3_bucket.raw.bucket
      REPORTS_BUCKET = aws_s3_bucket.reports.bucket
      DYNAMODB_TABLE = aws_dynamodb_table.scan_runs.id
    }
  }

  tags = {
    Name = "${var.project_name}-report"
  }
}

# ─────────────────────────────────────────
# S3 TRIGGER FOR REPORT LAMBDA
# When findings.zip lands in raw bucket
# S3 automatically calls the Report Lambda
# ─────────────────────────────────────────

resource "aws_lambda_permission" "allow_s3_report" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.report.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.raw.arn
}

# ─────────────────────────────────────────
# CONFIGURE LAMBDA
# Updates credentials.env on the scanner EC2
# via SSM when user submits DC IP + creds
# ─────────────────────────────────────────

data "archive_file" "configure" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/configure/handler.py"
  output_path = "${path.module}/../lambdas/configure/configure.zip"
}

resource "aws_lambda_function" "configure" {
  function_name    = "${var.project_name}-configure"
  role             = aws_iam_role.configure_lambda.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.configure.output_path
  source_code_hash = data.archive_file.configure.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      SCANNER_INSTANCE_ID = aws_instance.scanner.id
    }
  }

  tags = { Name = "${var.project_name}-configure" }
}

resource "aws_lambda_permission" "configure" {
  statement_id  = "AllowAPIGatewayConfigure"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.configure.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_s3_bucket_notification" "raw_findings" {
  bucket = aws_s3_bucket.raw.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.report.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "raw/"
    filter_suffix       = ".zip"
  }

  depends_on = [aws_lambda_permission.allow_s3_report]
}