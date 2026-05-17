<powershell>
# Runs on first boot — opens WinRM so Ansible can connect immediately.
# This is standard practice for Ansible-managed Windows on AWS.

# Allow WinRM through the firewall
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Configure WinRM for basic auth (Ansible default transport)
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# Extend the listener to all IPs
winrm set winrm/config/listener?Address=*+Transport=HTTP '@{Port="5985"}'

# Open port 5985 in the Windows firewall
netsh advfirewall firewall add rule `
  name="WinRM HTTP" `
  dir=in `
  action=allow `
  protocol=TCP `
  localport=5985

# Set execution policy so Ansible can run scripts
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

Write-Output "WinRM enabled — ready for Ansible"
</powershell>
