import json
import boto3
import os
import zipfile
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

# AWS clients
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# Environment variables set by Terraform
RAW_BUCKET = os.environ['RAW_BUCKET']
REPORTS_BUCKET = os.environ['REPORTS_BUCKET']
TABLE_NAME = os.environ['DYNAMODB_TABLE']

def lambda_handler(event, context):
    """
    Triggered automatically when findings.zip lands in the raw bucket.
    Reads the findings, scores them, generates a PDF, saves to reports bucket.
    """

    try:
        # Get bucket and file info from the S3 event
        record = event['Records'][0]
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']

        print(f"Processing findings from: s3://{bucket}/{key}")

        # Extract run_id from the key
        # Key format: raw/abc-123/findings.zip
        # We want: abc-123
        run_id = key.split('/')[1]

        print(f"Processing run_id: {run_id}")

        # Update DynamoDB to RUNNING
        update_status(run_id, 'PROCESSING')

        # Download the findings zip from S3
        zip_obj = s3.get_object(Bucket=bucket, Key=key)
        zip_bytes = zip_obj['Body'].read()

        # Read all JSON files from inside the zip
        findings = read_findings_from_zip(zip_bytes)

        print(f"Read {len(findings)} finding files")

        # Compute the security score
        score_data = compute_security_score(findings)

        print(f"Security score: {score_data['score']}/100")

        # Generate the PDF
        pdf_bytes = generate_pdf_report(run_id, score_data)

        # Upload PDF to reports bucket
        pdf_key = f"reports/{run_id}.pdf"
        s3.put_object(
            Bucket=REPORTS_BUCKET,
            Key=pdf_key,
            Body=pdf_bytes,
            ContentType='application/pdf'
        )

        print(f"PDF uploaded to: s3://{REPORTS_BUCKET}/{pdf_key}")

        # Update DynamoDB to COMPLETED
        update_status(run_id, 'COMPLETED', extra={
            'completed_at': datetime.utcnow().isoformat(),
            'security_score': str(score_data['score'])
        })

        return {'statusCode': 200, 'body': 'Report generated successfully'}

    except Exception as e:
        print(f"Error generating report: {str(e)}")
        # Try to mark as FAILED in DynamoDB
        try:
            update_status(run_id, 'FAILED', extra={'error': str(e)})
        except:
            pass
        raise e


def update_status(run_id, status, extra=None):
    """Updates the scan status in DynamoDB."""
    table = dynamodb.Table(TABLE_NAME)

    update_expr = "SET #s = :s"
    expr_names = {'#s': 'status'}
    expr_values = {':s': status}

    # Add any extra fields (completed_at, error, etc.)
    if extra:
        for key, value in extra.items():
            update_expr += f", #{key} = :{key}"
            expr_names[f'#{key}'] = key
            expr_values[f':{key}'] = value

    table.update_item(
        Key={'run_id': run_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values
    )


def read_findings_from_zip(zip_bytes):
    """
    Opens the findings.zip and reads all JSON files inside.
    BloodHound produces multiple JSON files:
      - computers.json
      - users.json
      - groups.json
      - domains.json
    """
    findings = {}

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for filename in zf.namelist():
            if filename.endswith('.json'):
                with zf.open(filename) as f:
                    try:
                        data = json.loads(f.read().decode('utf-8'))
                        # Use filename without extension as key
                        key = filename.replace('.json', '').split('/')[-1].lower()
                        findings[key] = data
                        print(f"Loaded: {filename}")
                    except json.JSONDecodeError as e:
                        print(f"Could not parse {filename}: {e}")

    return findings


def compute_security_score(findings):
    """
    Computes a security score from 0 (worst) to 100 (best).
    Finds specific misconfigurations in the target AD environment.

    Score starts at 100 and loses points for each finding.
    """

    score = 100
    issues = []
    stats = {}

    # ── USERS ──────────────────────────────────────────────
    users_data = findings.get('users', {})
    users = users_data.get('data', []) if isinstance(users_data, dict) else []
    stats['total_users'] = len(users)

    kerberoastable = []
    password_in_desc = []
    admin_users = []

    for user in users:
        props = user.get('Properties', {})

        # Kerberoastable: user has a Service Principal Name set
        # Attackers can request a ticket and crack it offline
        if props.get('hasspn', False):
            kerberoastable.append(props.get('name', 'Unknown'))
            score -= 15
            issues.append({
                'severity': 'CRITICAL',
                'type': 'Kerberoastable Account',
                'description': f"{props.get('name', 'Unknown')} has an SPN set and is vulnerable to Kerberoasting"
            })

        # Password stored in description field
        # A common AD misconfiguration
        desc = props.get('description', '') or ''
        if any(word in desc.lower() for word in ['password', 'pwd', 'pass', 'secret']):
            password_in_desc.append(props.get('name', 'Unknown'))
            score -= 10
            issues.append({
                'severity': 'HIGH',
                'type': 'Password in Description',
                'description': f"{props.get('name', 'Unknown')} has a password stored in their description field"
            })

        # Domain Admin members
        if props.get('admincount', False):
            admin_users.append(props.get('name', 'Unknown'))

    stats['kerberoastable_users'] = len(kerberoastable)
    stats['password_in_description'] = len(password_in_desc)
    stats['admin_users'] = len(admin_users)

    # ── COMPUTERS ──────────────────────────────────────────
    computers_data = findings.get('computers', {})
    computers = computers_data.get('data', []) if isinstance(computers_data, dict) else []
    stats['total_computers'] = len(computers)

    unconstrained = []
    for computer in computers:
        props = computer.get('Properties', {})

        # Unconstrained delegation: any user who authenticates
        # to this machine has their ticket stored — dangerous
        if props.get('unconstraineddelegation', False):
            # Skip DCs — they always have unconstrained delegation
            if not props.get('isdc', False):
                unconstrained.append(props.get('name', 'Unknown'))
                score -= 20
                issues.append({
                    'severity': 'CRITICAL',
                    'type': 'Unconstrained Delegation',
                    'description': f"{props.get('name', 'Unknown')} has unconstrained delegation enabled"
                })

    stats['unconstrained_delegation'] = len(unconstrained)

    # ── GROUPS ─────────────────────────────────────────────
    groups_data = findings.get('groups', {})
    groups = groups_data.get('data', []) if isinstance(groups_data, dict) else []

    da_members = 0
    for group in groups:
        props = group.get('Properties', {})
        if 'domain admins' in props.get('name', '').lower():
            members = group.get('Members', [])
            da_members = len(members)
            if da_members > 3:
                score -= 10
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'Excessive Domain Admin Members',
                    'description': f"Domain Admins group has {da_members} members — should be minimal"
                })

    stats['domain_admin_members'] = da_members

    # Floor the score at 0
    score = max(0, score)

    return {
        'score': score,
        'issues': issues,
        'stats': stats,
        'kerberoastable': kerberoastable,
        'password_in_desc': password_in_desc,
        'unconstrained': unconstrained
    }


def generate_pdf_report(run_id, score_data):
    """
    Generates a PDF security report using reportlab.
    Returns the PDF as bytes.
    """

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=inch,
        bottomMargin=inch
    )

    styles = getSampleStyleSheet()
    elements = []

    # ── Colors ─────────────────────────────────────────────
    dark_blue = HexColor('#2E5C8A')
    red = HexColor('#C0392B')
    orange = HexColor('#E67E22')
    green = HexColor('#27AE60')
    light_gray = HexColor('#F5F8FB')

    # ── Score color ────────────────────────────────────────
    score = score_data['score']
    if score >= 70:
        score_color = green
        risk_level = 'LOW RISK'
    elif score >= 40:
        score_color = orange
        risk_level = 'MEDIUM RISK'
    else:
        score_color = red
        risk_level = 'HIGH RISK'

    # ── Title ──────────────────────────────────────────────
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontSize=24,
        textColor=dark_blue,
        spaceAfter=6
    )
    elements.append(Paragraph("AegisAD Security Report", title_style))

    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=HexColor('#666666'),
        spaceAfter=20
    )
    elements.append(Paragraph(
        f"Scan ID: {run_id} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        subtitle_style
    ))

    elements.append(Spacer(1, 0.2 * inch))

    # ── Score box ──────────────────────────────────────────
    score_style = ParagraphStyle(
        'Score',
        parent=styles['Normal'],
        fontSize=48,
        textColor=score_color,
        alignment=1  # center
    )
    elements.append(Paragraph(f"{score}/100", score_style))

    risk_style = ParagraphStyle(
        'Risk',
        parent=styles['Normal'],
        fontSize=16,
        textColor=score_color,
        alignment=1,
        spaceAfter=20
    )
    elements.append(Paragraph(risk_level, risk_style))
    elements.append(Spacer(1, 0.3 * inch))

    # ── Stats table ────────────────────────────────────────
    heading_style = ParagraphStyle(
        'Heading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=dark_blue,
        spaceBefore=16,
        spaceAfter=8
    )
    elements.append(Paragraph("Environment Summary", heading_style))

    stats = score_data['stats']
    stats_data = [
        ['Metric', 'Count'],
        ['Total Users', str(stats.get('total_users', 0))],
        ['Total Computers', str(stats.get('total_computers', 0))],
        ['Domain Admin Members', str(stats.get('domain_admin_members', 0))],
        ['Kerberoastable Accounts', str(stats.get('kerberoastable_users', 0))],
        ['Passwords in Description', str(stats.get('password_in_description', 0))],
        ['Unconstrained Delegation', str(stats.get('unconstrained_delegation', 0))],
    ]

    stats_table = Table(stats_data, colWidths=[4 * inch, 2 * inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), dark_blue),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BACKGROUND', (0, 1), (-1, -1), light_gray),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, light_gray]),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CCCCCC')),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ── Issues ─────────────────────────────────────────────
    elements.append(Paragraph("Security Findings", heading_style))

    issues = score_data['issues']
    if not issues:
        elements.append(Paragraph(
            "No critical findings detected.",
            styles['Normal']
        ))
    else:
        severity_colors = {
            'CRITICAL': red,
            'HIGH': orange,
            'MEDIUM': HexColor('#F39C12'),
            'LOW': green
        }

        issues_data = [['Severity', 'Type', 'Description']]
        for issue in issues:
            issues_data.append([
                issue['severity'],
                issue['type'],
                issue['description']
            ])

        issues_table = Table(
            issues_data,
            colWidths=[1 * inch, 1.8 * inch, 3.7 * inch]
        )
        issues_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), dark_blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#CCCCCC')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, light_gray]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('WORDWRAP', (2, 1), (2, -1), True),
        ]))
        elements.append(issues_table)

    elements.append(Spacer(1, 0.3 * inch))

    # ── Recommendations ────────────────────────────────────
    elements.append(Paragraph("Recommendations", heading_style))

    recommendations = []
    if stats.get('kerberoastable_users', 0) > 0:
        recommendations.append(
            "Remove Service Principal Names (SPNs) from regular user accounts. "
            "Use managed service accounts (gMSA) instead."
        )
    if stats.get('password_in_description', 0) > 0:
        recommendations.append(
            "Remove all passwords from Active Directory description fields immediately. "
            "This information is readable by all domain users."
        )
    if stats.get('unconstrained_delegation', 0) > 0:
        recommendations.append(
            "Disable unconstrained delegation on all non-DC machines. "
            "Use constrained delegation or resource-based constrained delegation instead."
        )
    if stats.get('domain_admin_members', 0) > 3:
        recommendations.append(
            "Reduce Domain Admin membership to the minimum required. "
            "Use tiered administration and just-in-time privileged access."
        )
    if not recommendations:
        recommendations.append(
            "No immediate remediation required. Continue monitoring."
        )

    rec_style = ParagraphStyle(
        'Rec',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6,
        leftIndent=20
    )
    for i, rec in enumerate(recommendations, 1):
        elements.append(Paragraph(f"{i}. {rec}", rec_style))

    elements.append(Spacer(1, 0.5 * inch))

    # ── Footer ─────────────────────────────────────────────
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=HexColor('#999999'),
        alignment=1
    )
    elements.append(Paragraph(
        "Generated by AegisAD | Academic Security Assessment Platform | Not for production use",
        footer_style
    ))

    doc.build(elements)
    return buffer.getvalue()