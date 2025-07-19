---

# APT29 Threat Actor Profile

---

## ➀ PROJECT OVERVIEW

This report provides a structured threat actor profile on APT29 (also known as Cozy Bear), a Russian state-sponsored group recognised for its stealth, operational discipline, and persistent targeting of government, diplomatic, and research entities.

The purpose of this project is to simulate the kind of threat intelligence output a junior SOC analyst might be expected to produce in a real-world environment. The report includes:

- A summary of APT29's background and activity
- Key tactics, techniques, and procedures (TTPs)
- Known campaigns and targets
- Indicators of compromise (IOCs)
- Mapping to the MITRE ATT&CK framework
- Defensive recommendations for detection and response

This profile is designed to support SOC teams by adding context to alerts, informing threat hunting activities, and strengthening analyst awareness of adversary behaviours.

---

## ➁ WHO IS APT29?

APT29, also known as Cozy Bear, is a Russian state-sponsored threat group attributed to Russia’s Foreign Intelligence Service (SVR). Active since at least 2008, APT29 has been linked to numerous cyber espionage campaigns targeting Western governments, research institutions, healthcare organisations, and think tanks.

The group is known for its strategic intelligence-gathering operations and disciplined, stealthy approach. APT29 prioritises access longevity and operational secrecy over disruption or destruction. Its campaigns typically align with Russia’s geopolitical objectives.

Aliases for APT29 include:
- The Dukes
- Nobelium
- UNC2452
- SVR
- CozyDuke
- Yttrium

APT29 came to international attention for its role in the 2020 SolarWinds supply chain compromise and continues to evolve its techniques across multiple attack surfaces.

APT29 operations are characterised by:
- Custom malware and tailored infrastructure
- Advanced spear-phishing campaigns
- Abuse of legitimate tools and services (e.g., OAuth, Microsoft 365 APIs)
- Persistent access through stealth and low detection rates

Understanding the intent and methods of APT29 is essential for modern defence teams seeking to prioritise detection and protect high-value targets.

---

## ➂ TACTICS, TECHNIQUES, AND PROCEDURES (TTPs)

APT29’s operations align with a wide set of MITRE ATT&CK techniques. The group is known for stealthy, long-term access using minimal malware and careful abuse of legitimate services.

<details>
<summary><strong>Click to expand full list of tactics and techniques</strong></summary>

<br>

### Initial Access
- **Spearphishing via Service** — T1566.003  
  Targeted phishing emails with links to credential harvesting pages or malware delivery.
- **Valid Accounts** — T1078  
  Use of stolen credentials to log into VPNs, cloud platforms, and email accounts.

### Execution
- **PowerShell Execution** — T1059.001  
  Commands and payloads run via built-in Windows scripting tools.
- **Scheduled Task/Job** — T1053  
  Tasks scheduled for persistence or delayed execution of payloads.

### Persistence
- **Registry Run Keys / Startup Folder** — T1547.001  
  Registry edits used to maintain access after reboot.
- **Application Layer Protocol – HTTPS** — T1071.001  
  Encrypted HTTPS traffic used to blend C2 with legitimate traffic.

### Credential Access
- **Credential Dumping** — T1003  
  Dumping credentials from LSASS or Security Accounts Manager (SAM) database.
- **Token Impersonation** — T1134.001  
  Abusing OAuth tokens or access tokens to impersonate users in cloud environments.

### Command and Control
- **Web Service (C2)** — T1102  
  Using cloud services, blogs, and shared drives to route command and control.
- **Domain Fronting** — T1090.004  
  Hiding real C2 infrastructure behind trusted domains.

### Exfiltration
- **Exfiltration Over Web Services** — T1567.002  
  Data is exfiltrated through HTTPS or cloud apps like OneDrive and Dropbox.

</details>

APT29 frequently blends these techniques to evade detection, often relying on legitimate tools, platforms, and credentials rather than easily-flagged malware.
