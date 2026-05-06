import json
import boto3
import os

dynamodb = boto3.resource('dynamodb')

TABLE_NAME = os.environ['DYNAMODB_TABLE']

def lambda_handler(event, context):
    """
    Called every 3 seconds by the dashboard.
    Reads the scan status from DynamoDB and returns it.
    """

    try:
        # Get run_id from the URL
        # When browser calls GET /status/abc-123
        # API Gateway puts "abc-123" here
        run_id = event['pathParameters']['run_id']

        print(f"Checking status for run_id: {run_id}")

        # Read the row from DynamoDB
        table = dynamodb.Table(TABLE_NAME)
        response = table.get_item(Key={'run_id': run_id})

        # If run_id doesn't exist in DynamoDB
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': 'Scan not found',
                    'run_id': run_id
                })
            }

        # Return whatever is in DynamoDB for this run_id
        item = response['Item']
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'run_id': item['run_id'],
                'status': item['status'],
                'created_at': item.get('created_at', ''),
                'completed_at': item.get('completed_at', '')
            })
        }

    except Exception as e:
        print(f"Error checking status: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': str(e)
            })
        }