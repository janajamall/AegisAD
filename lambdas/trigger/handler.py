import json
import boto3
import uuid
import os
from datetime import datetime

# These clients talk to AWS services
dynamodb = boto3.resource('dynamodb')
ssm = boto3.client('ssm')

# These come from Lambda environment variables
# We'll set them in Terraform
TABLE_NAME = os.environ['DYNAMODB_TABLE']
INSTANCE_ID = os.environ['SCANNER_INSTANCE_ID']

def lambda_handler(event, context):
    """
    Called when user clicks Start Scan.
    Creates a run_id, saves to DynamoDB, fires SSM command.
    Returns run_id to the browser.
    """

    try:
        # Step 1: Generate unique ID for this scan
        run_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()

        print(f"Starting scan with run_id: {run_id}")

        # Step 2: Write PENDING status to DynamoDB
        table = dynamodb.Table(TABLE_NAME)
        table.put_item(Item={
            'run_id': run_id,
            'status': 'PENDING',
            'created_at': created_at
        })

        print(f"Written PENDING to DynamoDB for run_id: {run_id}")

        # Step 3: Tell the scanner EC2 to start
        # SSM Run Command sends a shell command to the Linux EC2
        ssm.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName='AWS-RunShellScript',
            Parameters={
              'commands': [
    f'bash /opt/scanner/run_scan.sh --run-id {run_id} >> /var/log/scanner_runs.log 2>&1'
]
            },
            Comment=f'AegisAD scan {run_id}'
        )

        print(f"SSM command sent to instance: {INSTANCE_ID}")

        # Step 4: Return run_id to the browser immediately
        # Don't wait for scan to finish — it takes 30-60 seconds
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'run_id': run_id,
                'status': 'PENDING',
                'message': 'Scan started successfully'
            })
        }

    except Exception as e:
        print(f"Error starting scan: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': str(e),
                'message': 'Failed to start scan'
            })
        }