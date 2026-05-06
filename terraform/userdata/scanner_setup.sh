#!/bin/bash
# AegisAD Scanner Setup Script
# Runs automatically when the EC2 instance first boots
# All output goes to /var/log/scanner_setup.log

exec > /var/log/scanner_setup.log 2>&1
set -e

echo "=== AegisAD Scanner Setup Starting ==="
echo "Timestamp: $(date)"

# ── Update system ──────────────────────────────────────────
echo "Updating system packages..."
apt-get update -y
apt-get upgrade -y

# ── Install Python and dependencies ───────────────────────
echo "Installing Python and pip..."
apt-get install -y python3 python3-pip python3-venv git unzip curl

# ── Install AWS CLI ───────────────────────────────────────
echo "Installing AWS CLI..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

# ── Install bloodhound-python ─────────────────────────────
echo "Installing bloodhound-python..."
pip3 install bloodhound boto3

# ── Create scanner directory ──────────────────────────────
echo "Creating scanner directory..."
mkdir -p /opt/scanner

# ── Write environment variables ───────────────────────────
# These are injected by Terraform templatefile()
echo "Writing environment configuration..."
cat > /opt/scanner/.env << 'ENVEOF'
export RAW_BUCKET="${raw_bucket}"
export DYNAMODB_TABLE="${dynamodb_table}"
export AWS_DEFAULT_REGION="${aws_region}"
export DC_DOMAIN="${dc_domain}"
# The security student fills these in manually:
# export DC_IP=""
# export AD_USERNAME=""
# export AD_PASSWORD=""
ENVEOF

# ── Write the run script loader ───────────────────────────
# This wrapper loads environment variables then runs the scanner
cat > /opt/scanner/run_scan.sh << 'RUNEOF'
#!/bin/bash
source /opt/scanner/.env
source /opt/scanner/credentials.env 2>/dev/null || true
python3 /opt/scanner/run.py "$@"
RUNEOF

chmod +x /opt/scanner/run_scan.sh

# ── Create empty credentials file ────────────────────────
# Security student fills this in after deployment
cat > /opt/scanner/credentials.env << 'CREDEOF'
# Fill in these values after deployment
# DO NOT commit this file to Git
export DC_IP="FILL_IN_DC_PRIVATE_IP"
export AD_USERNAME="FILL_IN_AD_USERNAME"
export AD_PASSWORD="FILL_IN_AD_PASSWORD"
CREDEOF

chmod 600 /opt/scanner/credentials.env

# ── Install CloudWatch agent ──────────────────────────────
echo "Installing CloudWatch agent..."
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb
rm amazon-cloudwatch-agent.deb

# ── Configure CloudWatch agent ─────────────────────────────
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CWEOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/scanner_setup.log",
            "log_group_name": "/aegisad/scanner/setup",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/scanner_runs.log",
            "log_group_name": "/aegisad/scanner/runs",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
CWEOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

echo "=== Setup Complete ==="
echo "Next steps for security student:"
echo "1. SSH or SSM into this instance"
echo "2. Edit /opt/scanner/credentials.env"
echo "3. Fill in DC_IP, AD_USERNAME, AD_PASSWORD"
echo "4. Upload /opt/scanner/run.py from the GitHub repo"
echo "Timestamp: $(date)"