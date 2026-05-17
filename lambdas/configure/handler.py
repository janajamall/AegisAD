import json
import boto3
import os

ssm = boto3.client('ssm')
INSTANCE_ID = os.environ['SCANNER_INSTANCE_ID']

def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body') or '{}')
        dc_ip      = body.get('dc_ip', '').strip()
        username   = body.get('ad_username', '').strip()
        password   = body.get('ad_password', '').strip()
        dc_domain  = body.get('dc_domain', 'north.sevenkingdoms.local').strip()

        if not dc_ip or not username or not password:
            return _resp(400, {'error': 'dc_ip, ad_username, and ad_password are required'})

        # Write credentials.env on the scanner EC2 via SSM
        command = (
            f"printf 'export DC_IP=\"{dc_ip}\"\\n"
            f"export AD_USERNAME=\"{username}\"\\n"
            f"export AD_PASSWORD=\"{password}\"\\n"
            f"export DC_DOMAIN=\"{dc_domain}\"\\n' "
            f"> /opt/scanner/credentials.env && chmod 600 /opt/scanner/credentials.env"
        )

        ssm.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [command]},
            Comment='AegisAD credentials update'
        )

        print(f"Credentials updated for DC_IP={dc_ip} user={username}")

        return _resp(200, {'message': 'Scanner credentials updated successfully'})

    except Exception as e:
        print(f"Error updating credentials: {e}")
        return _resp(500, {'error': str(e)})


def _resp(status, body):
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(body)
    }
