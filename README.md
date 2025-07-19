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

APT29’s operations align with a broad set of MITRE ATT&CK techniques. Their focus is long-term access and data exfiltration using stealthy, adaptable tools and methods.

This section groups observed TTPs by phase of the attack lifecycle.

---

**Initial Access**
- **Spearphishing via Service (T1566.003):** Targeted emails using malicious links or attachments to compromise government officials, researchers, and diplomats.
- **Valid Accounts (T1078):** Use of compromised credentials to log in via legitimate services, particularly Microsoft 365 and VPN portals.

**Execution**
- **Command and Scripting Interpreter – PowerShell (T1059.001):** Post-compromise execution of payloads using native Windows scripting.
- **Scheduled Task/Job (T1053):** Used for maintaining persistence and executing malware on a recurring basis.

**Persistence**
- **Service Registry Modification (T1547.001):** Modification of Windows registry keys to maintain access on compromised hosts.
- **Application Layer Protocol – HTTPS (T1071.001):** C2 traffic is hidden within legitimate HTTPS traffic to avoid detection.

**Credential Access**
- **Credential Dumping (T1003):** Tools like Mimikatz or custom scripts are used to extract credentials from LSASS or SAM databases.
- **Token Impersonation (T1134.001):** Abused OAuth tokens and service accounts to access cloud resources without triggering MFA.

**Command and Control**
- **Web Service (T1102):** Abuse of cloud platforms and compromised infrastructure to route C2 communications.
- **Domain Fronting (T1090.004):** Used to obscure true C2 infrastructure by masking traffic as if it were going to trusted services.

**Exfiltration**
- **Exfiltration Over Web Services (T1567.002):** Data is exfiltrated using encrypted HTTPS traffic or cloud file-sharing platforms.

APT29 regularly adapts its methods to evade detection, often blending in with legitimate user activity and trusted infrastructure.
