# Wazuh-Siem

## Objective

The goal of this project was to gain hands-on experience with SIEM by deploying Wazuh using its official OVA package. This involved exploring its core capabilities, understanding log ingestion and analysis workflows, and ultimately integrating Wazuh with my home lab environment—including a pfSense firewall—for real-time telemetry and threat detection.

## Sections learned about wazuh

- Installing agents Covering 
  - Ubuntu linux (DEBIAN) installation
  - Windows installation



## Installing agents
This section covers basic agent installation on Ubuntu (Debian-based) and Windows systems, as part of integrating Wazuh into a home lab SIEM setup. Here is the manual method as apposed to the method through wazuh interface. I found the wazuh interface did not work well for Ubuntu agent and required either installation of agent from the Wazuh home page or using a manual install.

### 🐧 Ubuntu (Debian-based)
Install Wazuh Agent:

curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.1.5-1_amd64.deb && \
sudo WAZUH_MANAGER='<WAZUH_MANAGER_IP>' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent.deb

sudo systemctl daemon-reload

sudo systemctl enable wazuh-agent

sudo systemctl start wazuh-agent

### Register Agent:

/var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP>

### Edit Configuration File:

nano /var/ossec/etc/ossec.conf

<img width="236" height="111" alt="image" src="https://github.com/user-attachments/assets/c900868f-e5b5-4128-a1db-52744aeb0d39" />


### Restart Agent:

sudo systemctl restart wazuh-agent

### Windows
Install Wazuh Agent:

powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.1.5-1.msi -OutFile wazuh-agent.msi
Start-Process -FilePath .\wazuh-agent.msi -ArgumentList "/q WAZUH_MANAGER='<WAZUH_MANAGER_IP>' WAZUH_REGISTRATION_SERVER='<WAZUH_MANAGER_IP>' WAZUH_AGENT_GROUP='default'" -Wait

### Register Agent:

#### powershell
& 'C:\Program Files (x86)\ossec-agent\agent-auth.exe' -m <WAZUH_MANAGER_IP>

### Edit Configuration File:

C:\Program Files (x86)\ossec-agent\ossec.conf

<img width="221" height="105" alt="image" src="https://github.com/user-attachments/assets/6506d35b-309e-4612-9260-7e1f8fec2533" />


### Restart Agent:

#### powershell
Restart-Service -Name wazuh
