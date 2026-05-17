# GOAD Lite (Testing Lab Only)

> ⚠️ **This is NOT a real implementation of [GOAD](https://github.com/Orange-Cyberdefense/GOAD).**
> It's a minimal stand-in we built to give AegisAD something realistic to scan during development.

## What this is

A two-VM AWS lab made up of:

- **DC01** (Windows Server 2019, `t3.medium`): Domain Controller for `north.sevenkingdoms.local`
- **SRV01** (Windows Server 2019, `t3.small`): Member server joined to the domain

The lab is populated by Ansible with intentional Active Directory misconfigurations
(Kerberoastable accounts, AS-REP roastable accounts, passwords stored in description
fields, unconstrained delegation, weak password policy, etc.) so the AegisAD scanner
has real findings to detect.

## What this is NOT

The official [GOAD project](https://github.com/Orange-Cyberdefense/GOAD) by Orange
Cyberdefense is a much larger and more realistic Active Directory pentest lab. The
full GOAD-Light topology is three VMs across two domains with about 25 named users,
trust relationships, vulnerable application stacks (MSSQL, IIS, WebDAV), ADCS
templates, an ELK monitoring layer, and many more attack paths.

We do not implement:

- The `sevenkingdoms.local` parent domain or the DC01 (kingslanding) server
- Cross-domain trust relationships
- The full GOAD user roster (we add a subset via `populate_users.yml`)
- MSSQL, IIS, WebDAV, or ADCS template installs
- ELK monitoring
- The Vagrant/Packer provisioning flow GOAD ships with

If you want the real thing, use the upstream repo. We chose the simplified version
for three reasons:

1. **Cost.** Three always-on Windows VMs is 50% more EC2 than two.
2. **Time.** The full GOAD Ansible role tree has many dependencies and was not a
   drop-in fit for our AWS-provisioned VMs (their inventory assumes Vagrant).
3. **Scope.** For testing AegisAD's detection logic, a single domain with planted
   misconfigurations is enough; every finding type still fires correctly.

## Deploying the lab

The lab Terraform reads the AegisAD VPC/subnet IDs as inputs, so deploy AegisAD first.

```bash
# 1. Edit terraform.tfvars with the AegisAD VPC and subnet IDs
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# fill in aegisad_vpc_id, aegisad_subnet_id, aegisad_scanner_sg_id, key_pair_name

# 2. Provision the VMs
cd terraform && terraform apply -auto-approve

# 3. Wait ~3-4 min for Windows to boot, then create ansible/inventory.yml
#    with DC01 and SRV01 public IPs + Administrator passwords (from outputs)

# 4. Configure AD
cd ../ansible
ansible-playbook -i inventory.yml playbooks/dc01_setup.yml
ansible-playbook -i inventory.yml playbooks/srv01_join.yml
ansible-playbook -i inventory.yml playbooks/populate_users.yml
ansible-playbook -i inventory.yml playbooks/vulnerabilities.yml
```

## Files

```
goad-lite/
├── terraform/                # Windows EC2 instances, EIPs, security group
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── provider.tf
│   ├── terraform.tfvars.example
│   └── userdata/             # Windows bootstrap scripts (WinRM, etc.)
└── ansible/
    ├── requirements.yml      # ansible.windows + community.windows collections
    └── playbooks/
        ├── dc01_setup.yml    # Promote DC01, create core users
        ├── srv01_join.yml    # Join SRV01 to the domain
        ├── populate_users.yml # Add the wider GoT user roster
        ├── vulnerabilities.yml # Plant intentional misconfigurations
        └── site.yml          # Run all of the above in order
```

The `inventory.yml` is not checked in because it contains the Administrator passwords
that EC2 generates per-instance. Build it from the Terraform outputs after `apply`.
