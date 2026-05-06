import json
import boto3
import os
from botocore.exceptions import ClientError

s3 = boto3.client('s3')

REPORTS_BUCKET = os.environ['REPORTS_BUCKET']

def lambda_handler(event, context):
    """
    Called when user clicks Download Report.
    Generates a 15-minute presigned URL for the PDF.
    Returns the URL to the browser.
    """

    try:
        # Get run_id from the URL
        # Browser calls GET /download/abc-123
        run_id = event['pathParameters']['run_id']

        print(f"Generating download URL for run_id: {run_id}")

        # The PDF lives at this key in the reports bucket
        pdf_key = f"reports/{run_id}.pdf"

        # Check the PDF exists before signing — generate_presigned_url
        # never contacts S3, so it succeeds even if the key is missing
        try:
            s3.head_object(Bucket=REPORTS_BUCKET, Key=pdf_key)
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return {
                    'statusCode': 404,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({
                        'error': 'Report not found',
                        'run_id': run_id
                    })
                }
            raise

        # Generate a presigned URL valid for 15 minutes
        presigned_url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': REPORTS_BUCKET,
                'Key': pdf_key
            },
            ExpiresIn=900  # 900 seconds = 15 minutes
        )

        print(f"Generated presigned URL for: {pdf_key}")

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'download_url': presigned_url,
                'expires_in': '15 minutes',
                'run_id': run_id
            })
        }

    except Exception as e:
        print(f"Error generating download URL: {str(e)}")
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