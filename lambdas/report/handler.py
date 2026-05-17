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

    # BloodHound names files like 20260506211054_users.json — strip the
    # timestamp prefix so we end up with keys like "users", "computers", etc.
    type_keywords = ['users', 'computers', 'groups', 'domains', 'gpos', 'ous', 'containers', 'trusts']

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for filename in zf.namelist():
            if filename.endswith('.json'):
                with zf.open(filename) as f:
                    try:
                        data = json.loads(f.read().decode('utf-8'))
                        basename = filename.split('/')[-1].replace('.json', '').lower()
                        key = next((kw for kw in type_keywords if kw in basename), basename)
                        findings[key] = data
                        print(f"Loaded: {filename} → key '{key}'")
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
    asrep_roastable = []
    admin_users = []
    stale_accounts = []
    password_not_required = []
    pwd_never_expires_admins = []
    admincount_ghosts = []
    user_constrained_delegation = []
    user_reversible_enc = []

    # System accounts that legitimately have SPNs — not real findings
    SYSTEM_ACCOUNTS = {'krbtgt', 'guest'}
    # Naming patterns that indicate this is a service/system account, not a real user.
    # Service accounts ARE expected to have SPNs — that's their job.
    SERVICE_PREFIXES = ('svc_', 'svc-', 'service_', 'sa_', 'sa-')
    SERVICE_KEYWORDS = ('service', 'mssql', 'iis', 'sql', 'webdav', 'http_', 'exchange')

    def looks_like_service_account(sam, props):
        if sam.startswith(SERVICE_PREFIXES):
            return True
        if any(kw in sam for kw in SERVICE_KEYWORDS):
            return True
        # Real users almost always have given/surname set
        if not props.get('givenname') and not props.get('surname'):
            return True
        return False

    for user in users:
        props = user.get('Properties', {})
        uname = props.get('name', 'Unknown')
        sam = (props.get('samaccountname') or uname.split('@')[0]).lower()

        # Skip machine accounts ($-suffixed) and built-in system accounts
        if sam.endswith('$') or sam in SYSTEM_ACCOUNTS:
            continue

        enabled = props.get('enabled', True)
        is_service = looks_like_service_account(sam, props)

        # Kerberoastable: user has a Service Principal Name set.
        # Service accounts SHOULD have SPNs — only flag regular user accounts.
        if props.get('hasspn', False) and enabled:
            kerberoastable.append(uname)
            if not is_service:
                issues.append({
                    'severity': 'HIGH',
                    'type': 'Kerberoastable User Account',
                    'description': f"{uname} is a regular user account with an SPN — unusual and Kerberoastable. Service accounts belong in a separate naming scheme.",
                    '_points': 12,
                })

        # AS-REP roastable: Kerberos pre-auth disabled (bypasses lockout entirely)
        if props.get('dontreqpreauth', False) and enabled:
            asrep_roastable.append(uname)
            issues.append({
                'severity': 'CRITICAL',
                'type': 'AS-REP Roastable Account',
                'description': f"{uname} has Kerberos pre-auth disabled — an attacker can request a hash without authenticating and crack it offline",
                '_points': 8,
            })

        # Password stored in description field
        desc = props.get('description', '') or ''
        if any(word in desc.lower() for word in ['password', 'pwd', 'pass', 'secret']):
            password_in_desc.append(uname)
            issues.append({
                'severity': 'HIGH',
                'type': 'Password in Description',
                'description': f"{uname} has a password leaking in their description field (readable by all domain users)",
                '_points': 7,
            })

        # Stale/inactive accounts — never logged on but still enabled
        if enabled and props.get('lastlogon', 0) == 0 and props.get('pwdlastset', 0) == 0:
            stale_accounts.append(uname)

        # Domain Admin members
        if props.get('admincount', False):
            admin_users.append(uname)

        # PasswordNotRequired — account can have an empty password
        if props.get('passwordnotreqd', False) and enabled:
            password_not_required.append(uname)
            issues.append({
                'severity': 'CRITICAL',
                'type': 'Password Not Required',
                'description': f"{uname} has the PasswordNotRequired flag set — the account can authenticate with an empty password",
                '_points': 12,
            })

        # Per-user reversible encryption
        if props.get('passwordstoredwithreversibleencryption', False) or props.get('reversibleencryption', False):
            user_reversible_enc.append(uname)
            issues.append({
                'severity': 'HIGH',
                'type': 'User Stores Password Reversibly',
                'description': f"{uname} has reversible password encryption enabled — anyone with DCSync can recover the plaintext",
                '_points': 8,
            })

        # AdminCount ghost — flagged as admin-protected but not actually in admin groups
        if props.get('admincount', False) and not is_service:
            # If user has admincount=1 we mark; if they're not in DA we'll cross-check after the group walk
            pass

        # User-level constrained delegation (allowedtodelegate)
        if props.get('allowedtodelegate'):
            targets = props.get('allowedtodelegate') or []
            if targets:
                user_constrained_delegation.append(uname)
                issues.append({
                    'severity': 'HIGH',
                    'type': 'Constrained Delegation on User',
                    'description': f"{uname} can delegate to {len(targets)} target(s) ({', '.join(targets[:2])}) — compromise of this account allows lateral movement",
                    '_points': 8,
                })

    if stale_accounts:
        issues.append({
            'severity': 'LOW',
            'type': 'Stale Accounts',
            'description': f"{len(stale_accounts)} enabled account(s) have never logged in — candidates for disable/removal",
            '_points': min(3, len(stale_accounts)),
        })

    stats['kerberoastable_users'] = len(kerberoastable)
    stats['asrep_roastable_users'] = len(asrep_roastable)
    stats['password_in_description'] = len(password_in_desc)
    stats['admin_users'] = len(admin_users)
    stats['stale_accounts'] = len(stale_accounts)
    stats['password_not_required'] = len(password_not_required)
    stats['user_reversible_enc'] = len(user_reversible_enc)
    stats['user_constrained_delegation'] = len(user_constrained_delegation)

    # ── DOMAIN PASSWORD POLICY ─────────────────────────────
    # BloodHound emits a domains.json with the pwd policy attributes
    domains_data = findings.get('domains', {})
    domains_list = domains_data.get('data', []) if isinstance(domains_data, dict) else []

    pwd_policy = {}
    if domains_list:
        dprops = domains_list[0].get('Properties', {})
        # pwdproperties bits: 1=complexity required, 16=reversible encryption
        pwd_props_bits = int(dprops.get('pwdproperties', 0) or 0)
        complexity_required = bool(pwd_props_bits & 1)
        reversible_enc = bool(pwd_props_bits & 16)

        min_pwd_length = int(dprops.get('minpwdlength', 0) or 0)
        lockout_threshold = int(dprops.get('lockoutthreshold', 0) or 0)
        max_pwd_age_100ns = int(dprops.get('maxpwdage', 0) or 0)
        # maxpwdage is a negative 100-nanosecond interval; convert to days
        max_pwd_age_days = abs(max_pwd_age_100ns) // (10_000_000 * 60 * 60 * 24) if max_pwd_age_100ns else 0

        pwd_policy = {
            'min_length': min_pwd_length,
            'complexity_required': complexity_required,
            'reversible_encryption': reversible_enc,
            'lockout_threshold': lockout_threshold,
            'max_pwd_age_days': max_pwd_age_days,
        }

        if min_pwd_length < 8:
            issues.append({
                'severity': 'HIGH',
                'type': 'Weak Password Length Policy',
                'description': f"Minimum password length is {min_pwd_length} — recommended 12+ characters",
                '_points': 8,
            })
        if not complexity_required:
            issues.append({
                'severity': 'HIGH',
                'type': 'Password Complexity Disabled',
                'description': "Domain policy does not enforce password complexity (mixed case, digits, symbols)",
                '_points': 8,
            })
        if reversible_enc:
            issues.append({
                'severity': 'CRITICAL',
                'type': 'Reversible Password Encryption Enabled',
                'description': "Domain stores passwords with reversible encryption — equivalent to plaintext",
                '_points': 12,
            })
        if lockout_threshold == 0:
            issues.append({
                'severity': 'MEDIUM',
                'type': 'No Account Lockout Policy',
                'description': "Lockout threshold is 0 — accounts can be brute-forced indefinitely",
                '_points': 7,
            })
        if max_pwd_age_days == 0 or max_pwd_age_days > 365:
            issues.append({
                'severity': 'LOW',
                'type': 'Weak Password Rotation Policy',
                'description': f"Maximum password age is {max_pwd_age_days or 'unlimited'} days — passwords are rarely or never rotated",
                '_points': 3,
            })

    stats['pwd_policy'] = pwd_policy

    # ── SCORE COMPUTATION ──────────────────────────────────
    # Cap per-category deductions so one bad area doesn't tank the score.
    CATEGORY_CAPS = {
        'identity': 35,   # kerberoastable, AS-REP, password-in-desc, stale
        'delegation': 30, # unconstrained delegation
        'privilege': 15,  # excessive Domain Admins
        'policy': 35,     # password policy issues
    }
    CATEGORY_MAP = {
        'Kerberoastable User Account':         'identity',
        'AS-REP Roastable Account':            'identity',
        'Password in Description':             'identity',
        'Stale Accounts':                      'identity',
        'Password Not Required':               'identity',
        'User Stores Password Reversibly':     'identity',
        'Unconstrained Delegation':            'delegation',
        'Constrained Delegation on User':      'delegation',
        'Excessive Domain Admin Members':      'privilege',
        'Weak Password Length Policy':         'policy',
        'Password Complexity Disabled':        'policy',
        'Reversible Password Encryption Enabled': 'policy',
        'No Account Lockout Policy':           'policy',
        'Weak Password Rotation Policy':       'policy',
    }
    category_totals = {c: 0 for c in CATEGORY_CAPS}
    for issue in issues:
        cat = CATEGORY_MAP.get(issue['type'])
        if cat:
            category_totals[cat] += issue.pop('_points', 0)

    for cat, total in category_totals.items():
        score -= min(total, CATEGORY_CAPS[cat])

    # ── COMPUTERS ──────────────────────────────────────────
    computers_data = findings.get('computers', {})
    computers = computers_data.get('data', []) if isinstance(computers_data, dict) else []
    stats['total_computers'] = len(computers)

    unconstrained = []
    for computer in computers:
        props = computer.get('Properties', {})
        name = props.get('name', 'Unknown')

        # DCs always have unconstrained delegation — required by Kerberos.
        # The `isdc` flag isn't reliably set, so check multiple signals.
        dn = (props.get('distinguishedname') or '').lower()
        sam = (props.get('samaccountname') or '').lower()
        is_dc = (
            props.get('isdc', False)
            or 'ou=domain controllers' in dn
            or int(props.get('primarygroupid', 0) or 0) == 516
            or sam.startswith('dc') and sam.endswith('$')
        )

        if props.get('unconstraineddelegation', False) and not is_dc:
            unconstrained.append(name)
            issues.append({
                'severity': 'CRITICAL',
                'type': 'Unconstrained Delegation',
                'description': f"{name} has unconstrained delegation — any user who authenticates to this host has their TGT cached and can be impersonated",
                '_points': 15,
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
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'Excessive Domain Admin Members',
                    'description': f"Domain Admins group has {da_members} members — should be minimal",
                    '_points': 7,
                })

    stats['domain_admin_members'] = da_members

    # Floor the score at 0
    score = max(0, score)

    return {
        'score': score,
        'issues': issues,
        'stats': stats,
        'kerberoastable': kerberoastable,
        'asrep_roastable': asrep_roastable,
        'password_in_desc': password_in_desc,
        'unconstrained': unconstrained
    }



def generate_pdf_report(run_id, score_data):
    """Generates a PDF security report using reportlab."""

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch
    )

    styles = getSampleStyleSheet()
    elements = []

    navy        = HexColor('#0F2A47')
    accent      = HexColor('#3B82F6')
    red         = HexColor('#DC2626')
    orange      = HexColor('#EA580C')
    yellow      = HexColor('#CA8A04')
    green       = HexColor('#16A34A')
    text_muted  = HexColor('#64748B')
    bg_light    = HexColor('#F8FAFC')
    border      = HexColor('#E2E8F0')

    score = score_data['score']
    stats = score_data['stats']
    issues = score_data['issues']

    if score >= 70:
        score_color, risk_level = green, 'LOW RISK'
    elif score >= 40:
        score_color, risk_level = orange, 'MEDIUM RISK'
    else:
        score_color, risk_level = red, 'HIGH RISK'

    severity_colors = {'CRITICAL': red, 'HIGH': orange, 'MEDIUM': yellow, 'LOW': green}

    # ── Header band ────────────────────────────────────────
    header_title = ParagraphStyle('HeaderTitle', parent=styles['Normal'],
        fontSize=22, textColor=white, fontName='Helvetica-Bold', leading=26)
    header_sub = ParagraphStyle('HeaderSub', parent=styles['Normal'],
        fontSize=9, textColor=HexColor('#CBD5E1'), leading=12)

    header_inner = Table([
        [Paragraph("AegisAD Security Report", header_title)],
        [Paragraph(
            f"Active Directory Assessment &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"Scan {run_id[:8]} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            header_sub)],
    ], colWidths=[7.3 * inch])
    header_inner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), navy),
        ('LEFTPADDING', (0, 0), (-1, -1), 24),
        ('RIGHTPADDING', (0, 0), (-1, -1), 24),
        ('TOPPADDING', (0, 0), (0, 0), 20),
        ('BOTTOMPADDING', (0, 1), (0, 1), 18),
        ('TOPPADDING', (0, 1), (0, 1), 4),
    ]))
    elements.append(header_inner)
    elements.append(Spacer(1, 0.25 * inch))

    # ── Score hero card ────────────────────────────────────
    score_huge = ParagraphStyle('ScoreHuge', parent=styles['Normal'],
        fontSize=56, textColor=score_color, fontName='Helvetica-Bold',
        leading=60, alignment=1)
    score_outof = ParagraphStyle('ScoreOutOf', parent=styles['Normal'],
        fontSize=12, textColor=text_muted, alignment=1, leading=14)
    risk_chip = ParagraphStyle('RiskChip', parent=styles['Normal'],
        fontSize=11, textColor=white, fontName='Helvetica-Bold',
        alignment=1, leading=14)
    summary_label = ParagraphStyle('SummaryLabel', parent=styles['Normal'],
        fontSize=8, textColor=text_muted, fontName='Helvetica-Bold',
        alignment=1, leading=10)
    summary_num = ParagraphStyle('SummaryNum', parent=styles['Normal'],
        fontSize=22, textColor=navy, fontName='Helvetica-Bold',
        alignment=1, leading=24)

    chip = Table([[Paragraph(risk_level, risk_chip)]], colWidths=[1.4 * inch])
    chip.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), score_color),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))

    score_cell = Table([
        [Paragraph(str(score), score_huge)],
        [Paragraph("out of 100", score_outof)],
        [Spacer(1, 6)],
        [chip],
    ], colWidths=[2.4 * inch])
    score_cell.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))

    def kpi(label, value, color=navy):
        return Table([
            [Paragraph(str(value), ParagraphStyle('k', parent=summary_num, textColor=color))],
            [Paragraph(label.upper(), summary_label)],
        ], colWidths=[1.55 * inch])

    kpi_row = Table([[
        kpi('Users', stats.get('total_users', 0)),
        kpi('Computers', stats.get('total_computers', 0)),
        kpi('Findings', len(issues), red if issues else green),
    ]], colWidths=[1.55 * inch] * 3)
    kpi_row.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))

    hero = Table([[score_cell, kpi_row]],
                 colWidths=[2.7 * inch, 4.6 * inch])
    hero.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, border),
        ('LINEBEFORE', (1, 0), (1, 0), 0.5, border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 22),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 22),
    ]))
    elements.append(hero)
    elements.append(Spacer(1, 0.25 * inch))

    section_style = ParagraphStyle('Section', parent=styles['Normal'],
        fontSize=13, textColor=navy, fontName='Helvetica-Bold',
        spaceBefore=8, spaceAfter=8, leading=16)

    # ── Environment summary ────────────────────────────────
    elements.append(Paragraph("Environment Summary", section_style))

    summary_rows = [
        ['Total Users',                  stats.get('total_users', 0)],
        ['Total Computers',              stats.get('total_computers', 0)],
        ['Domain Admin Members',         stats.get('domain_admin_members', 0)],
        ['AS-REP Roastable Accounts',    stats.get('asrep_roastable_users', 0)],
        ['Passwords in Description',     stats.get('password_in_description', 0)],
        ['Password Not Required',        stats.get('password_not_required', 0)],
        ['Reversible Encryption (Users)',stats.get('user_reversible_enc', 0)],
        ['Constrained Delegation (Users)', stats.get('user_constrained_delegation', 0)],
        ['Unconstrained Delegation',     stats.get('unconstrained_delegation', 0)],
        ['Stale Accounts',               stats.get('stale_accounts', 0)],
    ]
    summary_table = Table(
        [['METRIC', 'COUNT']] + [[r[0], str(r[1])] for r in summary_rows],
        colWidths=[5.3 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('FONTNAME', (1, 1), (1, -1), 'Helvetica-Bold'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('TEXTCOLOR', (1, 1), (1, -1), navy),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, bg_light]),
        ('GRID', (0, 0), (-1, -1), 0.25, border),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.25 * inch))

    # ── Password policy ────────────────────────────────────
    pp = stats.get('pwd_policy') or {}
    if pp:
        elements.append(Paragraph("Domain Password Policy", section_style))

        def status_chip(ok):
            color = green if ok else red
            label = "OK" if ok else "WEAK"
            chip_p = ParagraphStyle('chip', parent=styles['Normal'],
                fontSize=8, textColor=white, fontName='Helvetica-Bold',
                alignment=1, leading=10)
            t = Table([[Paragraph(label, chip_p)]], colWidths=[0.7 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), color),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            return t

        max_age = pp.get('max_pwd_age_days', 0)
        lockout = pp.get('lockout_threshold', 0)
        min_len = pp.get('min_length', 0)

        policy_rows = [
            ['POLICY', 'VALUE', 'STATUS'],
            ['Minimum Password Length', f"{min_len} chars", status_chip(min_len >= 8)],
            ['Complexity Required', 'Yes' if pp.get('complexity_required') else 'No',
             status_chip(pp.get('complexity_required', False))],
            ['Reversible Encryption', 'Enabled' if pp.get('reversible_encryption') else 'Disabled',
             status_chip(not pp.get('reversible_encryption', False))],
            ['Lockout Threshold', f"{lockout} attempts" if lockout else 'None',
             status_chip(lockout > 0)],
            ['Max Password Age', f"{max_age} days" if max_age else 'Unlimited',
             status_chip(0 < max_age <= 365)],
        ]
        policy_table = Table(policy_rows,
            colWidths=[3.5 * inch, 2.4 * inch, 1.4 * inch])
        policy_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), navy),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, bg_light]),
            ('GRID', (0, 0), (-1, -1), 0.25, border),
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(policy_table)
        elements.append(Spacer(1, 0.25 * inch))

    # ── Findings ───────────────────────────────────────────
    elements.append(Paragraph("Security Findings", section_style))

    if not issues:
        ok_style = ParagraphStyle('OK', parent=styles['Normal'],
            fontSize=10, textColor=text_muted, leading=14)
        elements.append(Paragraph(
            "No critical misconfigurations detected in this scan.", ok_style))
    else:
        sev_cell_style = ParagraphStyle('Sev', parent=styles['Normal'],
            fontSize=8, textColor=white, fontName='Helvetica-Bold',
            alignment=1, leading=10)
        type_style = ParagraphStyle('Type', parent=styles['Normal'],
            fontSize=10, textColor=navy, fontName='Helvetica-Bold', leading=12)
        desc_style = ParagraphStyle('Desc', parent=styles['Normal'],
            fontSize=9, textColor=HexColor('#334155'), leading=12)

        issues_data = [['', 'TYPE', 'DESCRIPTION']]
        row_styles = []
        for i, issue in enumerate(issues, start=1):
            sev = issue['severity']
            color = severity_colors.get(sev, text_muted)
            issues_data.append([
                Paragraph(sev, sev_cell_style),
                Paragraph(issue['type'], type_style),
                Paragraph(issue['description'], desc_style),
            ])
            row_styles.append(('BACKGROUND', (0, i), (0, i), color))

        issues_table = Table(issues_data,
            colWidths=[0.85 * inch, 1.85 * inch, 4.6 * inch])
        issues_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), navy),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('GRID', (0, 0), (-1, -1), 0.25, border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('LEFTPADDING', (1, 0), (-1, -1), 10),
            ('RIGHTPADDING', (1, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (1, 1), (-1, -1), [white, bg_light]),
        ] + row_styles))
        elements.append(issues_table)

    elements.append(Spacer(1, 0.25 * inch))

    # ── Recommendations ────────────────────────────────────
    elements.append(Paragraph("Recommendations", section_style))

    recs = []
    if stats.get('password_not_required', 0) > 0:
        recs.append("Audit accounts flagged PasswordNotRequired. Remove the flag unless a legitimate legacy system depends on it; rotate the password and re-enable the requirement.")
    if stats.get('user_reversible_enc', 0) > 0:
        recs.append("Disable AllowReversiblePasswordEncryption on individual users — it stores their password in a recoverable form on every DC.")
    if stats.get('user_constrained_delegation', 0) > 0:
        recs.append("Review accounts configured for constrained delegation. Confirm each target is still needed and consider switching to resource-based constrained delegation.")
    if stats.get('asrep_roastable_users', 0) > 0:
        recs.append("Re-enable Kerberos pre-authentication on all user accounts. Audit any account with DONT_REQ_PREAUTH set.")
    if stats.get('password_in_description', 0) > 0:
        recs.append("Strip all passwords from AD description fields immediately — they are readable by every authenticated domain user.")
    if stats.get('unconstrained_delegation', 0) > 0:
        recs.append("Disable unconstrained delegation on non-DC machines. Switch to constrained or resource-based constrained delegation.")
    if stats.get('domain_admin_members', 0) > 3:
        recs.append("Reduce Domain Admin membership. Adopt a tiered admin model with just-in-time privileged access.")
    if pp.get('min_length', 99) < 8:
        recs.append("Raise the domain minimum password length to at least 12 characters (NIST recommends 14+).")
    if not pp.get('complexity_required', True):
        recs.append("Enable password complexity requirements in the Default Domain Policy.")
    if pp.get('reversible_encryption'):
        recs.append("Disable reversible password encryption — it stores passwords in a recoverable form.")
    if pp.get('lockout_threshold', 0) == 0:
        recs.append("Configure an account lockout threshold (e.g. 5 attempts) to mitigate password spraying.")
    if not recs:
        recs.append("No immediate remediation required. Continue monitoring on a regular schedule.")

    rec_text = ParagraphStyle('Rec', parent=styles['Normal'],
        fontSize=10, textColor=HexColor('#334155'),
        spaceAfter=8, leading=14, leftIndent=14, bulletIndent=0)
    for i, rec in enumerate(recs, 1):
        elements.append(Paragraph(f"<b>{i}.</b> {rec}", rec_text))

    elements.append(Spacer(1, 0.4 * inch))

    footer_style = ParagraphStyle('Footer', parent=styles['Normal'],
        fontSize=8, textColor=text_muted, alignment=1, leading=10)
    elements.append(Paragraph(
        "Generated by AegisAD &middot; Academic Security Assessment Platform &middot; "
        "For research and educational use only",
        footer_style
    ))

    doc.build(elements)
    return buffer.getvalue()
