# Wazuh-Siem

## Objective

The goal of this project was to gain hands-on experience with SIEM by deploying Wazuh using its official OVA package. This involved exploring its core capabilities, understanding log ingestion and analysis workflows, and ultimately integrating Wazuh with my home lab environment—including a pfSense firewall—for real-time telemetry and threat detection.

## Sections learned about wazuh
- Install and update using OVA
- Installing agents Covering 
  - Ubuntu linux (DEBIAN) installation
    - Remove agents Ubuntu
  - Windows installation
    - Remove agent Windows
- Change IP agent point toward manger
- Set static Ip and Confirm DHCP is Off and Static IP is Set
  - When nmcli isn’t Available or Used
- Setup agents and manager for vulnerability scanning
  - Wazuh’s vulnerability detection module reporting outdated CVEs
  - Auditd Tracking system-level events like file access
  - Tcpdump test incoming traffic



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


## Remove agents Ubuntu

To remove the **Wazuh user agent** on Ubuntu using the **Wazuh manager**, follow these steps:

### **Using the CLI on the Wazuh Manager**
#### 1. **Access the Wazuh Manager**  
   Run the following command on the Wazuh server (bash)

   /var/ossec/bin/manage_agents

#### 2. **Select the Remove Option**  
   You'll see a menu like this:
  
   ****************************************
   * Wazuh v4.8.0 Agent manager. *
   * The following options are available: *
   ****************************************
   (A)dd an agent (A).
   (E)xtract key for an agent (E).
   (L)ist already added agents (L).
   (R)emove an agent (R).
   (Q)uit.
   Choose your action: A,E,L,R or Q:
   
   Type `R` to remove an agent.

#### 3. **Select the Agent to Remove**  
   The system will list available agents:
   
   Available agents:
   ID: 002, Name: Ubuntu, IP: any
   Provide the ID of the agent to be removed (or '\q' to quit): 002
   
   Enter the **agent ID** you want to remove.

#### 4. **Confirm Removal**  
   The system will ask for confirmation:
   
   Confirm deleting it?(y/n): y
   
   Type `y` to proceed.

#### 5. **Exit the Manager**  

   Once the agent is removed, exit the manager:
   
   manage_agents: Exiting.
   

### **Alternative: Using APT**
If you want to **completely uninstall** the Wazuh agent from Ubuntu, run (bash):

sudo apt-get remove --purge wazuh-agent

Then, delete any remaining files (bash):

sudo rm -rf /var/ossec/


For more details, check out [this guide](https://documentation.wazuh.com/current/installation-guide/uninstalling-wazuh/agent.html) or [this documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remove-agents/remove.html). 


## Windows:
Install Wazuh Agent (using powershell):

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.1.5-1.msi -OutFile wazuh-agent.msi
Start-Process -FilePath .\wazuh-agent.msi -ArgumentList "/q WAZUH_MANAGER='<WAZUH_MANAGER_IP>' WAZUH_REGISTRATION_SERVER='<WAZUH_MANAGER_IP>' WAZUH_AGENT_GROUP='default'" -Wait

### Register Agent (powershell):

'C:\Program Files (x86)\ossec-agent\agent-auth.exe' -m <WAZUH_MANAGER_IP>

### Edit Configuration File:

C:\Program Files (x86)\ossec-agent\ossec.conf

<img width="221" height="105" alt="image" src="https://github.com/user-attachments/assets/6506d35b-309e-4612-9260-7e1f8fec2533" />


### Restart Agent (powershell):

Restart-Service -Name wazuh


## Remove agent Windows

Removing the **Wazuh agent** on Windows is slightly different from Ubuntu. Here’s how you can do it:

### **Using the Wazuh Manager (CLI)**

#### 1. Open a **Command Prompt** as Administrator.

#### 2. Navigate to the Wazuh installation directory (bash):

   cd "C:\Program Files (x86)\ossec-agent"
   
#### 3. Run the **manage_agents** tool (bash):

   manage_agents.exe
   
#### 4. Select the **Remove Agent** option (`R`), then enter the agent ID.

#### 5. Confirm the removal when prompted.

### **Uninstalling via Windows Installer**

#### 1. Open **Command Prompt** as Administrator.

#### 2. Run the following command (bash):

   msiexec.exe /x wazuh-agent-4.11.1-1.msi /qn
   
   Replace `wazuh-agent-4.11.1-1.msi` with the correct version installed on your system.

### **Alternative: Using PowerShell**

#### 1. Open **PowerShell** as Administrator.
#### 2. Run (powershell):

   Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name='Wazuh Agent'" | ForEach-Object { $_.Uninstall() }
   
#### 3. Delete any remaining files (powershell):

   Remove-Item -Recurse -Force "C:\Program Files (x86)\ossec-agent"
   

For more details, check out [this guide](https://documentation.wazuh.com/current/installation-guide/uninstalling-wazuh/agent.html) or [this documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remove-agents/index.html).


## Change IP agent point toward manger

Switching the agent's manager target from 192.168.0.134 to 192.168.0.174. Here's the cleanest way to do it on Ubuntu:

### 1. Edit the agent config file (bash):

<img width="270" height="183" alt="image" src="https://github.com/user-attachments/assets/0cbd88e5-73b6-44b2-917e-296ebfb0b002" />


### 2. (Optional but recommended): If you're using agent-auth and want to ensure proper re-registration (bash):

sudo /var/ossec/bin/agent-auth -m 192.168.0.Y

### 3. Restart the agent (bash):

sudo systemctl restart wazuh-agent

Confirm the agent shows up on the manager (Y): On the manager (bash):

/var/ossec/bin/agent_control -l




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

## When nmcli isn’t Available or Used

	• On minimal server installations, NetworkManager (and therefore nmcli) may not be installed by default.
	• Cloud/OVA appliances (like Wazuh OVA) often rely on lighter or more predictable methods like:
		○ netplan (Ubuntu Server)
		○ systemd-networkd
		○ network-scripts (CentOS/older RHEL)
		○ Manual ip or ifconfig commands for custom scripts

When it is option:

Setting up a **static IP address** on Ubuntu ensures your system always has the same IP, which is useful for servers, remote access, and network stability. Here’s how you can do it:

### **Steps to Configure a Static IP on Ubuntu**
#### 1. **Identify Your Network Interface**  
   Run the following command to list available interfaces (bash)

   nmcli d
   
   or  

   ip link

   Find the name of the interface you want to configure (e.g., `enp0s3`).

### 2. **Edit the Netplan Configuration File**  
   Ubuntu uses **Netplan** for network configuration. Open the configuration file (bash)

   sudo nano /etc/netplan/01-netcfg.yaml

   If the file doesn’t exist, check `/etc/netplan/` for other `.yaml` files.

### 3. **Modify the Configuration**  
   Add or update the following lines (yaml):
   
   network:
     version: 2
     renderer: networkd
     ethernets:
       enp0s3:
         dhcp4: no
         addresses:
           - 192.168.1.100/24
         routes:
           - to: default
             via: 192.168.1.1
         nameservers:
           addresses: [8.8.8.8, 8.8.4.4]
   
   Replace `enp0s3` with your actual interface name and adjust the IP, gateway, and DNS settings.

### 4. **Apply the Changes**  
   Save the file and run (bash)
   
   sudo netplan apply

   This will apply the new network settings.



## Setup agents and manager for vulnerability scanning

To implement vulnerability scanning with Wazuh, here's a clear breakdown of what needs to be done on both the device running the agent and the Wazuh manager:


### Steps for the Device with the Agent Installed
#### 1. Install and Configure the Wazuh Agent:

   - Ensure the Wazuh agent is installed on the device.

   - Edit the agent's `ossec.conf` file (located at `/var/ossec/etc/ossec.conf` on Linux or in the Wazuh installation folder on Windows).

   - Enable the Syscollector module (xml):
 
	
<img width="190" height="129" alt="image" src="https://github.com/user-attachments/assets/3ed2ac30-5f7e-49b5-baa9-f624e89127b9" />

     

#### 2. To scan all ports

Regarding the <ports all="no">yes</ports> configuration in your ossec.conf file, this will enable the Wazuh agent to scan the ports on your system, but it restricts the scan to "yes" specifically, rather than all ports (all="no"). If your goal is to scan all ports, you should update this line to <ports all="yes">yes</ports>.
As for hotfixes, adding <hotfixes>yes</hotfixes> is recommended if you want the Wazuh agent's Syscollector module to gather information about system hotfixes. Hotfixes provide data about patches applied to your system, which is useful for security and compliance monitoring.



#### 3. Restart the Agent Service:

   - Restart the Wazuh agent to apply the new settings (bash)
 
     systemctl restart wazuh-agent
  

### Steps for the Wazuh Manager

#### 1. Enable Vulnerability Detection Module:

   - On the Wazuh manager, edit the `ossec.conf` file (located at `/var/ossec/etc/ossec.conf`).
   - Find the `<vulnerability-detector>` section and configure it like this (xml):
 
   <img width="214" height="145" alt="image" src="https://github.com/user-attachments/assets/7fe94161-f72e-4443-902b-02dcb1217b42" />

 

#### 2. Push Configuration to Agents (Optional for Default Settings):

   - If you'd like all agents to use the same configuration, you can set it in `/var/ossec/etc/shared/default/agent.conf` and restart the manager (bash):
     
     systemctl restart wazuh-manager
     

#### 3. Restart Wazuh Manager:
   - Apply the updated configuration (bash):
     
     systemctl restart wazuh-manager
     

<img width="304" height="337" alt="image" src="https://github.com/user-attachments/assets/5d1d9c57-baa6-4cb3-8967-0e658f6f97d9" />




### Verify and Initiate Scanning

#### 1. Ensure Agent-Manager Connection:

   - On the Wazuh dashboard, confirm that the agent is connected and sending data.
   - Go to **Endpoints** (or **Agents**) and check the status of the installed agent.

#### 2. Check Vulnerability Detection Alerts:
   - From the dashboard, navigate to the **Vulnerability Detection** section.
   - Review alerts for identified vulnerabilities on the agent's device.


## Wazuh’s vulnerability detection module reporting outdated CVEs

Wazuh’s vulnerability detection module reporting outdated CVEs for a newer Ubuntu system that has already patched them. Here's how to address it:

### Why It Happens

	• Wazuh uses NVD (National Vulnerability Database) and vendor feeds to match CVEs against installed packages.
	• Sometimes, version strings or kernel variants (like HWE) don’t align perfectly with CVE metadata.
	• This leads to false positives, especially on rolling or patched systems like Ubuntu 22.04 with HWE kernels.

### How to Reduce or Exclude False Positives

#### 1. Update Vulnerability Feed

Make sure your Wazuh manager is pulling the latest CVE data (bash):

/var/ossec/bin/wazuh-modulesd -f -c /var/ossec/etc/ossec.conf
Or restart the manager to refresh feeds.

#### 2. Use Package Exclusion
You can exclude specific packages from vulnerability scanning:
	• Create a file: /var/ossec/etc/shared/default/vulnerability-detection/packages-ignore
	• Add entries like:

linux-image-6.8.0-51-generic
linux-generic-hwe-22.04
This tells Wazuh to skip these packages during CVE matching.
#### 3. Suppress Specific CVEs

This feature is in development but not yet fully supported. As of now, you can't mark individual CVEs as false positives directly — but you can:
	• Create a custom rule that sets alert level to 0 for specific CVEs.
	• Example(xml)

<img width="480" height="98" alt="image" src="https://github.com/user-attachments/assets/82a642a3-7d9d-440e-90f3-bd7629201b9e" />


#### 4. Check Package Metadata

Ensure your system reports accurate package versions (bash)

dpkg -l | grep linux
uname -a
If your kernel is newer than the CVE’s affected version, it's likely a false positive.

### Reference Case

A similar issue was reported for CVE-2024-38541 on Ubuntu 22.04 with HWE kernel. The kernel was patched, but Wazuh still flagged it due to version mismatch.


## Auditd Tracking system-level events like file access

In Wazuh, auditd is the Linux Audit daemon that tracks system-level events like file access, command execution, and permission changes. Wazuh integrates with auditd to collect and analyze these events for security monitoring and compliance.

Here’s what it does in a nutshell:

	• Monitors system calls: Tracks actions like execve, open, chmod, etc., which are crucial for detecting suspicious behavior.
	• Captures user activity: You can log every command a user runs, including those with sudo or root privileges.
	• Feeds Wazuh alerts: Wazuh parses auditd logs (typically from /var/log/audit/audit.log) and applies rules to generate alerts for things like privilege escalation, unauthorized access, or tampering.
	• Supports custom rules: You can define your own audit.rules to monitor specific files, directories, or system calls, and tag them with keys like audit-wazuh-c for command execution.

For example, to track all commands run as root, you might add (bash)

-a exit,always -F arch=b64 -F euid=0 -S execve -k audit-wazuh-c
Then Wazuh can alert when something sketchy like ncat or tcpdump is executed unexpectedly.


## Tcpdump test incoming traffic

To capture ICMP packets from 192.168.0.254 using tcpdump, you can run:

sudo tcpdump -i eth0 icmp and src host 192.168.0.254
	• src host 192.168.0.254: Limits capture to packets originating from that IP.

If you want to see both requests and replies involving that IP:

sudo tcpdump -i eth0 icmp and host 192.168.0.254

And for verbose output with packet details:

sudo tcpdump -vv -i eth0 icmp and host 192.168.0.254


To filter traffic by port 514 using tcpdump, you’ll want to specify the protocol and port in your capture expression. Port 514 is commonly used for syslog over UDP or TCP, depending on the setup.

How to send a basic packet for test purpose
Send TCP packet
echo "Test message to port 514" | nc 192.168.0.x 514
Send UDP packet 
echo "Test message" | nc -u -q1 192.168.0.x 514

### Examples for Capturing Port 514 Traffic

#### 1. UDP traffic on port 514

sudo tcpdump -i eth0 udp port 514

#### 2. TCP traffic on port 514

sudo tcpdump -i eth0 tcp port 514

#### 3. All traffic involving port 514 (TCP or UDP)

sudo tcpdump -i eth0 port 514
To capture traffic from 192.168.0.x on port 514:

sudo tcpdump -i eth0 src host 192.168.0.x and port 514
Or to capture any traffic involving 192.168.0.x and port 514:

sudo tcpdump -i eth0 host 192.168.0.x and port 514

#### Add Verbosity or Save to File
	• Verbose output (bash):
	
sudo tcpdump -vv -i eth0 port 514
	• Show the packet contents a better option
	sudo tcpdump -nn -A -i <interface> udp port 514
	• Write to file for later analysis (bash):

sudo tcpdump -i eth0 port 514 -w syslog_capture.pcap


## Common Reasons pfSense Logs Don’t Reach Wazuh Manager

### 1. Remote Logging Misconfiguration
	• Go to Status → System Logs → Settings → Remote Logging Options
	• Enable Remote Logging
	• Set Log Format to BSD
	• Add your Wazuh Manager’s IP and port (usually 514/UDP)
	• Check Everything to forward all logs

### 3. Missing Hostname in Syslog Headers
	• pfSense often omits hostnames in syslog headers, which breaks Wazuh’s pre-decoder
	• Workaround: Use Syslog-ng on pfSense to reformat logs before sending to Wazuh

### 4. Firewall Blocking Port 514
	• On Wazuh Manager, ensure port 514/UDP is open (bash):

sudo ufw allow 514/udp

### 5. No Decoder or Rule Match
	• Wazuh needs the 0455-pfsense_decoders.xml and 0540-pfsense_rules.xml files
	• You can override default rules to log drop events by removing <options>no_log</options>


## Check syslog and Enable syslog collection on wazuh

### Troubleshooting Access to archives.log

#### 1. Check File Existence

Run:
ls -l /var/ossec/logs/archives/
If archives.log isn’t listed, it may not be created yet—especially if **logall** <!-- <logall> --> isn’t enabled or no logs are being archived.
2. Verify Permissions

Try:
	• sudo ls -l /var/ossec/logs/archives/archives.log
If the file exists but you still can’t read it, check ownership:
	• stat /var/ossec/logs/archives/archives.log

You may need to run as root or ensure your user is in the ossec group.
3. Enable Archiving
In /var/ossec/etc/ossec.conf, confirm this block exists (xml):
<!-- <global>
  <logall>yes</logall>
</global> -->
<img width="159" height="59" alt="image" src="https://github.com/user-attachments/assets/c09ca37b-68c4-444e-a19e-f5bdbec00696" />

Then restart the manager:
	• sudo systemctl restart wazuh-manager
4. Check for Log Rotation
Sometimes archives.log is rotated and renamed. Try:
bash
	• ls /var/ossec/logs/archives/archives.log*
You might find archives.log.1, .gz, or other rotated versions.


