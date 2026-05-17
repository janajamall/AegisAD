# ─────────────────────────────────────────
# HTTP API (simpler and cheaper than REST API)
# ─────────────────────────────────────────

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
  description   = "AegisAD scan API"

  # CORS configuration
  # Allows the dashboard (on a different domain) to call this API
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }

  tags = {
    Name = "${var.project_name}-api"
  }
}

# ─────────────────────────────────────────
# STAGE
# Think of this as the "version" of the API
# $default means it's the only version
# ─────────────────────────────────────────

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  tags = {
    Name = "${var.project_name}-api-stage"
  }
}

# ─────────────────────────────────────────
# INTEGRATIONS
# Tells API Gateway which Lambda to call
# for each route
# ─────────────────────────────────────────

resource "aws_apigatewayv2_integration" "trigger" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.trigger.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "status" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.status.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "download" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.download.invoke_arn
  payload_format_version = "2.0"
}

# ─────────────────────────────────────────
# ROUTES
# Maps URL paths to integrations
# ─────────────────────────────────────────

resource "aws_apigatewayv2_route" "scan" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /scan"
  target    = "integrations/${aws_apigatewayv2_integration.trigger.id}"
}

resource "aws_apigatewayv2_route" "status" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /status/{run_id}"
  target    = "integrations/${aws_apigatewayv2_integration.status.id}"
}

resource "aws_apigatewayv2_route" "download" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /download/{run_id}"
  target    = "integrations/${aws_apigatewayv2_integration.download.id}"
}

# ─────────────────────────────────────────
# PERMISSIONS
# Allow API Gateway to invoke each Lambda
# ─────────────────────────────────────────

resource "aws_lambda_permission" "trigger" {
  statement_id  = "AllowAPIGatewayTrigger"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trigger.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "status" {
  statement_id  = "AllowAPIGatewayStatus"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.status.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "configure" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.configure.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "configure" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /configure"
  target    = "integrations/${aws_apigatewayv2_integration.configure.id}"
}

resource "aws_lambda_permission" "download" {
  statement_id  = "AllowAPIGatewayDownload"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.download.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}