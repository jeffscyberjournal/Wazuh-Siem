# Wazuh-Siem

## Objective

The goal of this project was to gain hands-on experience with SIEM by deploying Wazuh using its official OVA package. This involved exploring its core capabilities, understanding log ingestion and analysis workflows, and ultimately integrating Wazuh with my home lab environment—including a pfSense firewall—for real-time telemetry and threat detection.

## Sections learned about wazuh
- [Installation Of Agents](Installation-of-agents/README.md)
  - Install and update using OVA <!--29-->
  - Installing agents <!--85-->
    - Ubuntu linux (DEBIAN) installation 
      - Remove agents Ubuntu
    - Windows installation
      - Remove agent Windows
- [Wazuh Manager Connectivity](Wazuh-Manager-Connectivity/README.md) 
  - Change IP agent point toward manager <!--243-->
  - Wazuh dashboard server is not responding to changes  <!--266-->
  - Check Agent Connection from Manage <!--273-->
  - Secure Syslog Configuration for pfSense → Wazuh Manager <!--356-->
  - Ensure IP is static for wazuh  <!-400-->
  - Set static Ip and Confirm DHCP is Off and Static IP is Set  <!--460--> 
  - When nmcli isn’t Available or Used
- [Setup agents and manager for vulnerability scanning](Setup-agents-and-manager-for-vulnerability-scanning/README.md) 
  - Wazuh’s vulnerability detection module reporting outdated CVEs
  - Auditd Tracking system-level events like file access
  - Tcpdump test incoming traffic
  - Common Reasons pfSense Logs Don’t Reach Wazuh Manager
  - Check syslog and Enable syslog collection on wazuh  
- Configure alerting based on alert level to email
- [Event Logging Guide](Event-Logging/README.md)
  - Force log gathering from manager to agents
  - Check Linux and Windows agent logging
  - Check Wazuh manager working
  - Auditd Tracking system-level events like file access
  - Making rules to detect applications run orsudo operation examples
  - Check syslog and Enable syslog collection on wazuh
  - Common Reasons pfSense Logs Don’t Reach Wazuh Manager
  - Tcpdump test incoming traffic

 	









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


## pfsense push a single log on port 514 udp to wazuh manager

### the pfSense shell log test log (bash):

logger -n 192.168.0.x -P 514 -d "Test log from pfSense to Wazuh"

### Breakdown of the Command

 - logger: Built-in utility to send syslog messages.
 - -n 192.168.0.x: Target IP address (your Wazuh server).
 - -P 514: Destination port (default for syslog over UDP).
 - -d: Use UDP (datagram) instead of TCP.
 - "Test log from pfSense to Wazuh": The actual message.

#### This sends a single syslog-formatted message directly to Wazuh. You can verify receipt on the Wazuh server using (bash):

sudo tcpdump -i any port 514 -n

Look for the incoming packet and confirm it contains your test message.

#### Would you like help crafting a custom log format or automating periodic log pushes for testing Wazuh rules?

logger -n 192.168.0.x -P 514 -d "Test log from pfSense to Wazuh" -n is illegal comand
You're right, and great catch — the -n flag isn’t valid in pfSense’s version of logger. The BSD-based logger used in pfSense (FreeBSD) differs from the GNU/Linux version.
Here’s the correct way to push a single log entry from pfSense to your Wazuh server via UDP port 514:

### Use with nc (Netcat) for Direct UDP Log Transmission (bash)

	• echo "<13>Test log from pfSense to Wazuh" | nc -u -w1 192.168.0.x 514

### Explanation
 - **<13>** is the syslog priority value (facility=USER, severity=NOTICE).
 - **nc -u**: Sends via UDP
 - **-w1**: Waits 1 second before timing out
 - **192.168.0.x 514**: Target Wazuh IP and port

This bypasses the logger utility and sends a properly formatted syslog message directly to Wazuh.

### To Confirm It's Received

#### On Wazuh (bash):

sudo tcpdump -i any port 514 -n

Look for your "Test log from pfSense to Wazuh" entry.


## Configure alerting based on alert level to email


To send email alerts to `myemail@emailprovider.com` for alerts above a certain severity level, follow these steps:

---

### Step 1: Enable Email Notifications

Edit `/var/ossec/etc/ossec.conf` and modify the `<global>` block:

```xml
<global>
  <email_notification>yes</email_notification>
  <smtp_server>localhost</smtp_server> <!-- Or your SMTP relay -->
  <email_from>wazuh@yourdomain.com</email_from>
  <email_to>myemail@emailprovider.com</email_to>
  <email_maxperhour>100</email_maxperhour>
</global>
```
Replace localhost with your SMTP server if you're not using a local relay like Postfix.

email_from must match the sender address configured in your SMTP relay.

Step 2: Set Alert Threshold
Still in ossec.conf, configure the <alerts> block:

```xml
<alerts>
  <email_alert_level>10</email_alert_level>
</alerts>
This means only alerts with level 10 or higher will trigger an email.
```

You can adjust the level from 1 (low) to 16 (critical), depending on your noise tolerance.

### Step 3: Restart the Wazuh Manager
Apply the changes (bash):

sudo systemctl restart wazuh-manager





