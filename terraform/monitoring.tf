# ─────────────────────────────────────────
# LOG GROUPS
# One per Lambda — stores all print() output
# Automatically deleted after 30 days
# ─────────────────────────────────────────

resource "aws_cloudwatch_log_group" "trigger" {
  name              = "/aws/lambda/${var.project_name}-trigger"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "status" {
  name              = "/aws/lambda/${var.project_name}-status"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "download" {
  name              = "/aws/lambda/${var.project_name}-download"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "report" {
  name              = "/aws/lambda/${var.project_name}-report"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "scanner_runs" {
  name              = "/aegisad/scanner/runs"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "scanner_setup" {
  name              = "/aegisad/scanner/setup"
  retention_in_days = 30
}

# ─────────────────────────────────────────
# DASHBOARD
# Visual overview in AWS Console
# Go to CloudWatch → Dashboards → aegisad
# ─────────────────────────────────────────

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        x    = 0
        y    = 0
        width  = 12
        height = 6
        properties = {
          title  = "Lambda Invocations"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "Invocations",
              "FunctionName", "${var.project_name}-trigger",
              { label = "Trigger", color = "#7c8cff" }],
            ["AWS/Lambda", "Invocations",
              "FunctionName", "${var.project_name}-report",
              { label = "Report", color = "#22c55e" }],
            ["AWS/Lambda", "Invocations",
              "FunctionName", "${var.project_name}-status",
              { label = "Status", color = "#94a3b8" }],
            ["AWS/Lambda", "Invocations",
              "FunctionName", "${var.project_name}-download",
              { label = "Download", color = "#f59e0b" }]
          ]
          view   = "timeSeries"
          period = 300
          stat   = "Sum"
        }
      },
      {
        type = "metric"
        x    = 12
        y    = 0
        width  = 12
        height = 6
        properties = {
          title  = "Lambda Errors"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "Errors",
              "FunctionName", "${var.project_name}-trigger",
              { label = "Trigger Errors", color = "#ef4444" }],
            ["AWS/Lambda", "Errors",
              "FunctionName", "${var.project_name}-report",
              { label = "Report Errors", color = "#f97316" }]
          ]
          view   = "timeSeries"
          period = 300
          stat   = "Sum"
        }
      },
      {
        type = "metric"
        x    = 0
        y    = 6
        width  = 12
        height = 6
        properties = {
          title  = "Lambda Duration (ms)"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "Duration",
              "FunctionName", "${var.project_name}-trigger",
              { label = "Trigger", color = "#7c8cff" }],
            ["AWS/Lambda", "Duration",
              "FunctionName", "${var.project_name}-report",
              { label = "Report", color = "#22c55e" }]
          ]
          view   = "timeSeries"
          period = 300
          stat   = "Average"
        }
      },
      {
        type = "metric"
        x    = 12
        y    = 6
        width  = 12
        height = 6
        properties = {
          title  = "S3 Raw Bucket — Objects"
          region = var.aws_region
          metrics = [
            ["AWS/S3", "NumberOfObjects",
              "BucketName", "${var.project_name}-raw-${data.aws_caller_identity.current.account_id}",
              "StorageType", "AllStorageTypes",
              { label = "Raw Findings", color = "#7c8cff" }]
          ]
          view   = "timeSeries"
          period = 86400
          stat   = "Average"
        }
      }
    ]
  })
}

# ─────────────────────────────────────────
# ALARM
# Fires if Report Lambda errors more than
# once in a 5-minute window
# Visible in CloudWatch → Alarms
# ─────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "report_errors" {
  alarm_name          = "${var.project_name}-report-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Report Lambda is failing — check CloudWatch logs"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = "${var.project_name}-report"
  }
}

resource "aws_cloudwatch_metric_alarm" "trigger_errors" {
  alarm_name          = "${var.project_name}-trigger-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Trigger Lambda is failing — check CloudWatch logs"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = "${var.project_name}-trigger"
  }
}