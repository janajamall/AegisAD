# Gets the AWS account ID automatically
# Used to make bucket names unique across all of AWS
data "aws_caller_identity" "current" {}

# ─────────────────────────────────────────
# BUCKET 1: Raw scan findings
# ─────────────────────────────────────────
resource "aws_s3_bucket" "raw" {
  bucket        = "${var.project_name}-raw-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

# Encrypt everything stored in this bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access — this bucket is private
resource "aws_s3_bucket_public_access_block" "raw" {
  bucket                  = aws_s3_bucket.raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Auto-delete raw findings after 30 days
resource "aws_s3_bucket_lifecycle_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id

  rule {
    id     = "expire-old-findings"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
  }
}

# ─────────────────────────────────────────
# BUCKET 2: PDF reports
# ─────────────────────────────────────────
resource "aws_s3_bucket" "reports" {
  bucket        = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access — users get PDFs via presigned URLs only
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─────────────────────────────────────────
# BUCKET 3: Dashboard (public website)
# ─────────────────────────────────────────
resource "aws_s3_bucket" "dashboard" {
  bucket        = "${var.project_name}-dashboard-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

# Turn this bucket into a website
resource "aws_s3_bucket_website_configuration" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

# This bucket IS public — it's the dashboard website
resource "aws_s3_bucket_public_access_block" "dashboard" {
  bucket                  = aws_s3_bucket.dashboard.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Policy that allows anyone to READ files from the dashboard bucket
resource "aws_s3_bucket_policy" "dashboard_public_read" {
  bucket     = aws_s3_bucket.dashboard.id
  depends_on = [aws_s3_bucket_public_access_block.dashboard]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.dashboard.arn}/*"
      }
    ]
  })
}