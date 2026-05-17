#!/usr/bin/env python3
"""
AegisAD Scanner Script
Runs on the Linux scanner EC2 via SSM Run Command.
Usage: python3 /opt/scanner/run.py --run-id <run_id>
"""

import argparse
import boto3
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime

# ─────────────────────────────────────────
# Configuration — set as environment variables
# on the EC2 instance (done in Terraform user_data)
# ─────────────────────────────────────────
RAW_BUCKET = os.environ.get('RAW_BUCKET', '')
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', '')
AWS_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')

# AD credentials — set manually on the EC2
# by the security student after deployment
DC_IP = os.environ.get('DC_IP', '')
DC_DOMAIN = os.environ.get('DC_DOMAIN', 'north.sevenkingdoms.local')
AD_USERNAME = os.environ.get('AD_USERNAME', '')
AD_PASSWORD = os.environ.get('AD_PASSWORD', '')

# AWS clients
s3 = boto3.client('s3', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)


def log(message):
    """Print with timestamp — shows up in CloudWatch logs."""
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}", flush=True)


def update_status(run_id, status, error=None):
    """Update the scan status in DynamoDB."""
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        update_expr = "SET #s = :s, updated_at = :u"
        expr_names = {'#s': 'status'}
        expr_values = {
            ':s': status,
            ':u': datetime.utcnow().isoformat()
        }

        if error:
            update_expr += ", error_message = :e"
            expr_values[':e'] = error

        table.update_item(
            Key={'run_id': run_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values
        )
        log(f"DynamoDB updated: {run_id} → {status}")

    except Exception as e:
        log(f"WARNING: Could not update DynamoDB: {e}")


def run_bloodhound(run_id):
    """
    Runs bloodhound-python against the DC.
    Returns path to output directory.
    """
    output_dir = f"/tmp/bloodhound_{run_id}"
    os.makedirs(output_dir, exist_ok=True)

    log(f"Running bloodhound-python against {DC_DOMAIN} at {DC_IP}")

    # Ensure DC hostname resolves — bloodhound-python requires FQDN for -dc
    dc_hostname = f"dc01.{DC_DOMAIN}"
    hosts_entry = f"{DC_IP} {dc_hostname} dc01\n"
    with open("/etc/hosts", "r") as f:
        hosts = f.read()
    if dc_hostname not in hosts:
        with open("/etc/hosts", "a") as f:
            f.write(hosts_entry)
        log(f"Added {dc_hostname} → {DC_IP} to /etc/hosts")

    # Build the bloodhound-python command
    # Note: --outputdir is not supported; cd into the dir instead
    cmd = [
        "python3", "-m", "bloodhound",
        "-u", AD_USERNAME,
        "-p", AD_PASSWORD,
        "-d", DC_DOMAIN,
        "-dc", dc_hostname,
        "-ns", DC_IP,
        "--auth-method", "ntlm",
        "-c", "All",
        "--zip",
    ]

    log(f"Command: bloodhound-python -u {AD_USERNAME} -d {DC_DOMAIN} -c All")

    # Run the command with cwd so output lands in output_dir
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,  # 10 minute timeout
        cwd=output_dir
    )

    # Log all output — shows up in CloudWatch
    if result.stdout:
        for line in result.stdout.split('\n'):
            if line.strip():
                log(f"BH: {line}")

    if result.stderr:
        for line in result.stderr.split('\n'):
            if line.strip():
                log(f"BH-ERR: {line}")

    if result.returncode != 0:
        raise Exception(
            f"bloodhound-python failed with exit code {result.returncode}: {result.stderr}"
        )

    log("bloodhound-python completed successfully")
    return output_dir


def find_zip_file(output_dir):
    """
    bloodhound-python with --zip creates a zip file.
    Find it in the output directory.
    """
    for filename in os.listdir(output_dir):
        if filename.endswith('.zip'):
            return os.path.join(output_dir, filename)

    # If no zip found, bloodhound ran without --zip
    # Create one manually from the JSON files
    log("No zip found — creating one from JSON files")
    zip_path = f"{output_dir}/findings.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        for filename in os.listdir(output_dir):
            if filename.endswith('.json'):
                zf.write(
                    os.path.join(output_dir, filename),
                    filename
                )
    return zip_path


def upload_to_s3(run_id, zip_path):
    """Upload the findings zip to S3."""
    s3_key = f"raw/{run_id}/findings.zip"

    log(f"Uploading findings to s3://{RAW_BUCKET}/{s3_key}")

    s3.upload_file(
        zip_path,
        RAW_BUCKET,
        s3_key
    )

    log(f"Upload complete: {s3_key}")
    return s3_key


def cleanup(run_id):
    """Remove temp files from /tmp."""
    import shutil
    output_dir = f"/tmp/bloodhound_{run_id}"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
        log(f"Cleaned up temp files: {output_dir}")


def validate_config():
    """Check all required environment variables are set."""
    missing = []
    if not RAW_BUCKET:
        missing.append('RAW_BUCKET')
    if not DYNAMODB_TABLE:
        missing.append('DYNAMODB_TABLE')
    if not DC_IP:
        missing.append('DC_IP')
    if not AD_USERNAME:
        missing.append('AD_USERNAME')
    if not AD_PASSWORD:
        missing.append('AD_PASSWORD')

    if missing:
        raise Exception(
            f"Missing required environment variables: {', '.join(missing)}"
        )


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='AegisAD Scanner')
    parser.add_argument(
        '--run-id',
        required=True,
        help='Unique scan run ID from DynamoDB'
    )
    args = parser.parse_args()
    run_id = args.run_id

    log(f"Scanner started for run_id: {run_id}")

    try:
        # Step 1: Validate config
        validate_config()

        # Step 2: Update DynamoDB → RUNNING
        update_status(run_id, 'RUNNING')

        # Step 3: Run bloodhound-python
        output_dir = run_bloodhound(run_id)

        # Step 4: Find the output zip
        zip_path = find_zip_file(output_dir)
        log(f"Found findings zip: {zip_path}")

        # Step 5: Upload to S3
        upload_to_s3(run_id, zip_path)

        # Step 6: Clean up temp files
        cleanup(run_id)

        # Step 7: Log success
        # Note: we do NOT update DynamoDB to COMPLETED here
        # The Report Lambda does that after generating the PDF
        log(f"Scanner finished successfully for run_id: {run_id}")
        log("Report Lambda will now generate the PDF automatically")

        sys.exit(0)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        update_status(run_id, 'FAILED', error=str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()