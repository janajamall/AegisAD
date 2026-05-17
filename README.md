# AegisAD

**Cloud-native Active Directory security assessment platform built on AWS.**

Users trigger automated scans against a target AD environment through a web dashboard and receive PDF reports identifying attack paths, Kerberoastable accounts, unconstrained delegation, and other misconfigurations.

---

## Architecture

```
Browser (S3 dashboard)
    │  POST /scan
    ▼
API Gateway  ──►  Trigger Lambda  ──►  SSM Run Command
                       │
                       ▼
                   DynamoDB (PENDING)
                       │
                  Scanner EC2 (Linux)
                  bloodhound-python
                       │ RUNNING
                       ▼
                    S3 raw bucket  (findings.zip)
                       │ S3 event trigger
                       ▼
                  Report Lambda
                  (parse findings → score → PDF)
                       │ COMPLETED
                       ▼
                DynamoDB ◄──── S3 reports bucket
                       │
               Download Lambda (presigned URL)
                       │
                    Browser
```

**AWS services used:**

| Service | Role |
|---|---|
| API Gateway (HTTP) | Exposes `/scan`, `/status/{id}`, `/download/{id}` |
| Lambda (×4) | Trigger, Report, Status, Download (all serverless) |
| EC2 (Ubuntu) | Runs bloodhound-python scanner |
| S3 (×3) | Raw findings, PDF reports, dashboard hosting |
| DynamoDB | Tracks scan state: PENDING > RUNNING > PROCESSING > COMPLETED |
| SSM | Sends scan commands to EC2 without SSH keys |
| CloudWatch | Logs, metrics dashboard, error alarms |
| IAM | Least-privilege roles for every Lambda and EC2 |
| VPC | Isolated network with public subnet and security groups |

---

## Project Structure

```
AegisAD/
├── terraform/              # Infrastructure as Code; deploys all AWS resources
│   ├── provider.tf
│   ├── vpc.tf
│   ├── ec2.tf
│   ├── lambda.tf
│   ├── apigateway.tf
│   ├── dynamodb.tf
│   ├── S3.tf
│   ├── iam.tf
│   ├── monitoring.tf
│   ├── security_groups.tf
│   ├── variables.tf
│   ├── output.tf
│   └── userdata/
│       └── scanner_setup.sh
├── lambdas/
│   ├── trigger/handler.py  # Writes PENDING to DynamoDB, fires SSM
│   ├── status/handler.py   # Reads DynamoDB status
│   ├── download/handler.py # Returns presigned S3 URL
│   └── report/handler.py   # Parses findings, scores AD, generates PDF
├── scanner/
│   └── run.py              # Runs bloodhound-python, uploads to S3
├── dashboard/
│   └── index.html          # Single-page UI hosted on S3
└── docs/
    ├── Arch/               # Architecture diagrams
    └── security/           # Security analysis
```

---

## Prerequisites

- Docker (for the deployment image)
- AWS credentials with AdministratorAccess (or scoped IAM)
- AWS CLI installed locally

---

## Deployment

### 1. Build the deployment image

```bash
# From the project root (one directory above AegisAD/)
cd docker/
docker build -t aegisad-tools .
```

### 2. Deploy infrastructure

```bash
docker run --rm -it \
  -v /path/to/AegisAD:/workspace \
  -e AWS_ACCESS_KEY_ID=YOUR_KEY \
  -e AWS_SECRET_ACCESS_KEY=YOUR_SECRET \
  -e AWS_DEFAULT_REGION=us-east-1 \
  aegisad-tools bash

# Inside the container:
cd /workspace/terraform
terraform init
terraform plan
terraform apply
terraform output    # save all outputs
```

### 3. Upload scanner script to EC2

```bash
# Upload run.py via S3 (no SSH key needed)
aws s3 cp scanner/run.py s3://REPLACE_raw_bucket_name/config/run.py

aws ssm send-command \
  --instance-ids REPLACE_scanner_instance_id \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["aws s3 cp s3://REPLACE_raw_bucket_name/config/run.py /opt/scanner/run.py && chmod +x /opt/scanner/run.py"]' \
  --region us-east-1
```

### 4. Update dashboard and upload

Edit `dashboard/index.html` line ~322 and replace `API_URL` with the value from `terraform output api_url`.

```bash
aws s3 cp dashboard/index.html s3://REPLACE_dashboard_bucket_name/index.html \
  --content-type text/html
```

### 5. Configure scanner credentials

```bash
# Open a shell on the scanner EC2 via SSM
aws ssm start-session --target REPLACE_scanner_instance_id --region us-east-1

# Inside the session:
nano /opt/scanner/credentials.env
# Fill in:
#   export DC_IP="TARGET_DC_IP"
#   export AD_USERNAME="your_ad_user"
#   export AD_PASSWORD="your_ad_password"
```

### 6. Open the dashboard

Navigate to the URL from `terraform output dashboard_url`. Click **Start Scan**.

---

## How a scan works

1. User clicks **Start Scan** in the dashboard
2. API Gateway calls the Trigger Lambda
3. Trigger Lambda writes `PENDING` to DynamoDB and fires an SSM Run Command on the scanner EC2
4. Scanner EC2 runs `bloodhound-python`, updates DynamoDB to `RUNNING`, uploads `findings.zip` to S3
5. S3 upload event automatically triggers the Report Lambda
6. Report Lambda parses the BloodHound JSON, scores the AD environment, generates a PDF, stores it in S3, updates DynamoDB to `COMPLETED`
7. Dashboard polls the Status Lambda every 3 seconds and shows progress
8. User clicks **Download Report**. The Download Lambda returns a presigned S3 URL and the PDF opens in the browser

---

## Security design

- **IAM least privilege**: every Lambda and the scanner EC2 have narrowly scoped roles. No role has more access than needed for its specific function
- **No SSH keys**: the scanner EC2 is accessed only via AWS Systems Manager. No open port 22 in production
- **Encryption at rest**: S3 buckets use AES-256 SSE; DynamoDB uses AWS-managed encryption
- **Private findings**: the raw findings bucket and reports bucket block all public access; users get PDFs through time-limited presigned URLs only
- **Security groups**: scanner EC2 can only receive SSH from a configured admin IP; Windows AD VMs only accept traffic from the scanner security group

---

## Testing lab

A minimal Active Directory testing environment lives in [`goad-lite/`](./goad-lite/).

**It is not a full implementation of [GOAD](https://github.com/Orange-Cyberdefense/GOAD).** It's a two-VM AWS lab (DC01 + SRV01) with intentional misconfigurations planted via Ansible so the AegisAD scanner has something realistic to detect during development. See [`goad-lite/README.md`](./goad-lite/README.md) for what is and isn't implemented.

---

## Team

- Leen Almousa, Cloud architecture, Lambda functions, dashboard, IaC
- Jana Falah, Active Directory lab integration, security analysis, BloodHound integration

---

*Educational project. Not for production use.*
