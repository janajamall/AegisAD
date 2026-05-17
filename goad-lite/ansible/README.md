# GOAD Lite — Ansible Playbooks

The playbooks are NOT written here. Clone the official GOAD repo and use its playbooks:

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
```

GOAD Lite playbooks live at: `ad/GOAD-Light/providers/aws/`

## Running with the Docker image

```bash
# From project root
docker run --rm -it \
  -v $(pwd)/goad-lite:/workspace/goad-lite \
  -v /path/to/GOAD:/workspace/GOAD \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  goad-cloud-tools bash

# Inside the container:
cd /workspace/GOAD
ansible-galaxy install -r requirements.yml
ansible-playbook -i /workspace/goad-lite/ansible/inventory.yml ad/GOAD-Light/providers/aws/site.yml
```

## inventory.yml

Update `inventory.yml` in this directory with IPs from `terraform output` before running.
