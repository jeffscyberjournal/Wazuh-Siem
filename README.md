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





