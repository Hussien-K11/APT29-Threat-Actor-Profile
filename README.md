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
APT29 regularly adapts its methods to evade detection, often blending in with legitimate user activity and trusted infrastructure.

---

## ➃ KNOWN CAMPAIGNS

APT29 has been attributed to several high-impact cyber espionage campaigns. These operations reflect the group’s strategic focus on intelligence gathering, long-term access, and stealthy intrusion methods.

<details>
<summary><strong>Click to view detailed summaries of major APT29 campaigns</strong></summary>

<br>

### SolarWinds Supply Chain Compromise (2020)

**Summary:**  
APT29 (tracked as UNC2452/Nobelium) compromised the build environment of SolarWinds' Orion platform. They inserted a backdoor (SUNBURST) into legitimate software updates, which were then distributed to over 18,000 customers.

**Target:**  
U.S. federal agencies, global IT firms, think tanks

**Initial Access:**  
Trojanised updates delivered via SolarWinds’ software supply chain

**Tactics Observed:**  
- Supply Chain Compromise – T1195.002  
- Command and Control via HTTPS – T1071.001  
- Credential Access and Lateral Movement  
- Use of the SUNBURST and TEARDROP malware families

**Outcome:**  
Long-term, covert access to sensitive systems across U.S. infrastructure. Prompted global reviews of supply chain security.

**Reference:**  
[FireEye Analysis](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)

---

### COVID-19 Vaccine Espionage Campaign (2020)

**Summary:**  
APT29 targeted academic and healthcare organisations involved in COVID-19 vaccine development. Spearphishing emails and custom malware (WellMess, WellMail) were used to attempt data theft.

**Target:**  
Pharmaceutical firms, universities, and research labs in the US, UK, and Canada

**Initial Access:**  
Spearphishing and credential harvesting

**Tactics Observed:**  
- Spearphishing via Service – T1566.003  
- Use of custom malware (WellMess, WellMail)  
- Credential Theft and Privilege Escalation

**Outcome:**  
Revealed the risk of state-sponsored espionage during a global health crisis. Attribution led to coordinated public advisories from multiple countries.

**Reference:**  
[UK NCSC Advisory](https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development)

</details>

---

## ➄ INDICATORS OF COMPROMISE (IOCs)

APT29 campaigns have produced a range of observable artefacts — known as Indicators of Compromise — which can be used to detect or investigate their activity. These include IP addresses, domains, file hashes, and registry paths.

The following are example IOCs associated with past APT29 operations. These values should be treated as historical references and validated before use in any live detection pipeline.

<details>
<summary><strong>Click to view sample IOCs</strong></summary>

<br>

| Type     | Value                            | Context / Description                         |
|----------|----------------------------------|-----------------------------------------------|
| Domain   | `login-microsoft-secure[.]com`   | Credential harvesting domain (WellMess C2)    |
| Domain   | `cloudsync-update[.]net`         | Likely used for C2 communication              |
| IP       | `185.225.69.69`                  | Identified C2 infrastructure (WellMail)       |
| IP       | `104.248.120.232`                | Historical C2 server                          |
| SHA256   | `e3b0c44298fc1c149afbf4c8996fb924...` | SUNBURST dropper sample hash                  |
| SHA1     | `af4edbf1cfc09485b50e5a683eb9d93df38dc437` | Linked to credential harvesting payload       |

</details>

> **Analyst Note:**  
> IOCs are context-sensitive and often time-limited. Use them alongside behavioural analytics, TTPs, and log correlation for effective detection. When possible, prioritise mapping IOCs to observed techniques (e.g., MITRE) rather than relying on standalone indicators.


---

## ➅ MITRE ATT&CK MAPPING

APT29’s tactics and techniques align with a broad set of MITRE ATT&CK entries across multiple phases of the intrusion lifecycle. Mapping their known behaviours to the MITRE framework supports defenders in building proactive detection rules, assessing threat coverage, and improving response strategies.

The following table outlines key techniques attributed to APT29, grouped by attack phase.

| Tactic              | Technique                                | MITRE ID      |
|---------------------|-------------------------------------------|---------------|
| Initial Access       | Spearphishing via Service                | T1566.003      |
| Initial Access       | Valid Accounts                          | T1078          |
| Execution            | PowerShell                              | T1059.001      |
| Persistence          | Scheduled Task/Job                      | T1053          |
| Persistence          | Registry Run Keys / Startup Folder      | T1547.001      |
| Credential Access    | Credential Dumping                      | T1003          |
| Credential Access    | Token Impersonation                     | T1134.001      |
| Command & Control    | Web Service                             | T1102          |
| Command & Control    | Domain Fronting                         | T1090.004      |
| Exfiltration         | Exfiltration Over Web Services          | T1567.002      |
| Supply Chain         | Compromise of Software Supply Chain     | T1195.002      |

> **Analyst Note:**  
> Mapping adversary behaviour to MITRE techniques gives SOC teams a common language for threat analysis and detection. Unlike IOCs, which can quickly expire or be changed, TTPs provide behavioural insights that remain more stable over time. This allows detection engineers to focus on “how” the threat operates, not just “what” it uses.


---

## ➆ DEFENSIVE RECOMMENDATIONS

Based on APT29’s observed tactics, the following defensive measures are recommended to strengthen detection and response within a SOC environment:

### Initial Access
- Implement email filtering rules to detect spearphishing lures containing suspicious links or file types
- Flag logins from new geographic locations or unfamiliar devices, especially if tied to privileged accounts

### Credential Access
- Monitor for use of credential dumping tools (e.g., access to LSASS, use of Mimikatz-like behaviours)
- Alert on anomalous OAuth token use, particularly for cloud services like Microsoft 365

### Persistence
- Monitor registry changes to common persistence keys (`Run`, `RunOnce`, etc.)
- Detect creation of scheduled tasks tied to unknown binaries or scripts

### Command and Control
- Monitor for domain fronting, or encrypted HTTPS traffic to rare or unclassified domains
- Inspect beacon-like behaviour (low, regular traffic bursts) during off-peak hours

### Exfiltration
- Monitor outbound file transfers to cloud storage services (e.g., OneDrive, Dropbox) from sensitive systems
- Correlate sudden data access with external upload patterns

### General Recommendations
- Align internal detection rules with MITRE ATT&CK techniques (e.g., tag alerts with TTP IDs like T1071.001)
- Conduct regular threat hunting based on TTP behaviour, not just IOCs

> **Analyst Note:**  
> Defensive strategies should prioritise **behaviour-based detection** over static indicators. While IOCs are helpful, APT29 frequently shifts infrastructure and tooling. Building detections around their techniques ensures longer-lasting, adaptable defences.


---