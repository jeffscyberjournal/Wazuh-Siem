# Wazuh-Siem

## Objective

The goal of this project was to gain hands-on experience with SIEM by deploying Wazuh using its official OVA package. This involved exploring its core capabilities, understanding log ingestion and analysis workflows, and ultimately integrating Wazuh with my home lab environment—including a pfSense firewall—for real-time telemetry and threat detection.

## Sections learned about wazuh
- Install and update using OVA
- Installing agents Covering 
  - Ubuntu linux (DEBIAN) installation
  - Windows installation
- Set static Ip and Confirm DHCP is Off and Static IP is Set


## Installation 
So far I tried installation on proxmox and virtualbox installations:

### For VirtualBox 
Download: the Wazuh OVA file from the official Wazuh website.

Import: the OVA file using the "File > Import Appliance" option in VirtualBox.

### For Proxmox
Since Proxmox does not directly support OVA files, you need to convert them. 

Extract: the disk image (VMDK file) from the downloaded OVA file. 

Create: a new virtual machine in Proxmox. 

Attach: the extracted VMDK disk image to the new Proxmox VM. 
Alternatively, use a tool or the tar and qm importovf commands to import and convert the OVA into a format Proxmox can use. 

### For VMware ESXi

Download: the Wazuh OVA file from the official Wazuh website. 

Import: the OVA directly into VMware ESXi using the platform's interface, typically via the "File > Open" or similar "Import Appliance" optio


## update using OVA

The OVA from the official Wazuh website I used was a RHEL/CentOS-based system, so this will require using yum:

### 1. Stop Wazuh services (Bash):

sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-indexer

### 2. Update the Wazuh repository (if needed, in bash):

sudo yum clean all
sudo yum makecache

### 3. Upgrade Wazuh components (Bash):

sudo yum update wazuh-manager wazuh-dashboard wazuh-indexer

### 4. Start services again (Bash):

sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-dashboard

### 5. Verify the upgrade: You can check the version with (Bash):

/var/ossec/bin/wazuh-control info
If you’re running a multi-node setup or using custom configurations, it’s best to follow the official Wazuh upgrade guide to avoid version mismatches or config overwrites.


## Installing agents
This section covers basic agent installation on Ubuntu (Debian-based) and Windows systems, as part of integrating Wazuh into a home lab SIEM setup. Here is the manual method as apposed to the method through wazuh interface. I found the wazuh interface did not work well for Ubuntu agent and required either installation of agent from the Wazuh home page or using a manual install. Installing the agents appeared straight forward through the wazuh interface, working perfectly for Windows except Ubuntu agent seemed to fail. The following manual method works fine for either.

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

### Windows:
Install Wazuh Agent (using powershell):

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


## Set static Ip and Confirm DHCP is Off and Static IP is Set

### 1. List Network Config Files (bash)
   
ls /etc/systemd/network/
Look for files like 10-eth0.network, 20-static.network, etc.

### 2. Inspect the Active Config (bash)

cat /etc/systemd/network/*.network
You're looking for something like:

ini
[Match]
Name=eth0
[Network]
DHCP=no
Address=192.168.x.x/24
Gateway=192.168.x.x
DNS=8.8.8.8
	• DHCP=no confirms DHCP is disabled.
	• Address= confirms static IP is set.

### 3. Check Runtime Status (bash)

networkctl status eth0
This shows whether the interface is using static or dynamic addressing.

### 4. Verify IP Assignment (bash)

ip a s eth0
You should see:

inet 192.168.x.x/24 scope global eth0
If it says dynamic, DHCP is still active. If it says valid_lft forever, it’s static.

### 5. Confirm Gateway and DNS (bash)

ip r
cat /etc/resolv.conf

