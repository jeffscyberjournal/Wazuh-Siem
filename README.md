# Wazuh-Siem

## Objective

The goal of this project was to gain hands-on experience with SIEM by deploying Wazuh using its official OVA package. This involved exploring its core capabilities, understanding log ingestion and analysis workflows, and ultimately integrating Wazuh with my home lab environment—including a pfSense firewall—for real-time telemetry and threat detection.

## Sections learned about wazuh
- [Installation Of Agents](Installation-of-agents/README.md)
  - 2.1 Install and update using OVA 
  - 2.2 Installing agents 
    - 2.2.1 Ubuntu linux (DEBIAN) installation 
    - 2.2.2 Remove agents Ubuntu
    - 2.2.3 Windows installation
    - 2.2.4 Remove agent Windows
- [Wazuh Manager Connectivity](Wazuh-Manager-Connectivity/README.md) 
  - Change IP agent point toward manager 
  - Wazuh dashboard server is not responding to changes  
  - Check Agent Connection from Manage 
  - Secure Syslog Configuration for pfSense → Wazuh Manager 
  - Ensure IP is static for wazuh  
  - Set static Ip and Confirm DHCP is Off and Static IP is Set 
  - When nmcli isn’t Available or Used
- [Setup agents and manager for vulnerability scanning](Setup-agents-and-manager-for-vulnerability-scanning/README.md) 
  - Wazuh’s vulnerability detection module reporting outdated CVEs
  - Auditd Tracking system-level events like file access
  - Common Reasons pfSense Logs Don’t Reach Wazuh Manager
  - Check syslog and Enable syslog collection on wazuh  
- [Event Logging Guide](Event-Logging/README.md)
  - 2.1 Change IP agent point toward manager 
  - 2.2 Wazuh dashboard server is not responding to changes  
  - 2.3 Check Agent Connection from Manage 
  - 2.4 Secure Syslog Configuration for pfSense → Wazuh Manager 
  - 2.5 Ensure IP is static for wazuh 
  - 2.6 Set static Ip and Confirm DHCP is Off and Static IP is Set  
  - 2.7 When nmcli isn’t Available or Used
  - 2.8 Tcpdump test incoming traffic
  - 2.9 pfsense push a single log on port 514 udp to wazuh manager
  - 2.10 Configure alerting based on alert level to email

 	
