# Unauthorized-Nmap-Usage

# 🗂️ Threat Hunt Report — Unauthorized Nmap Usage

---

## 📋 Table of Contents

- [STEP 1 — Initial Detection](#step-1--initial-detection)
- [STEP 2 — Execution Evidence](#step-2--execution-evidence)
- [STEP 3 — Command Line Analysis](#step-3--command-line-analysis)
- [STEP 4 — Network Activity Check](#step-4--network-activity-check)
- [STEP 5 — Employee & Management Response](#step-5--employee--management-response)
- [Recommended Actions](#recommended-actions)
- [Status](#status)

---

## ✅ STEP 1 — Initial Detection

**Scenario:** Unauthorized installation of network scanning tool (**Nmap**)  
**Environment:** Onboarded VM — `john-target1-vm`  
**Tools:** Microsoft Defender for Endpoint (MDE) and KQL

The first step in a threat investigation is detecting potentially malicious or unauthorized activity. In this case, we begin by identifying whether a known offensive security tool — nmap — was introduced into the environment. Nmap is commonly used for network scanning and reconnaissance, which can be a red flag if it's not part of the standard toolset for the user or organization.
Using Microsoft Defender for Endpoint and KQL, we query for file creation and download events related to Nmap, which helps us pinpoint when, where, and by whom the tool was introduced.

## 🔍 Initial Query

## 🔍 STEP 1 — Initial Detection

### 🧠 Explanation  
The first step in a threat investigation is detecting potentially malicious or unauthorized activity. In this case, we begin by identifying whether a known offensive security tool — `nmap` — was introduced into the environment. Nmap is commonly used for network scanning and reconnaissance, which can be a red flag if it's not part of the standard toolset for the user or organization.  
Using Microsoft Defender for Endpoint and KQL, we query for file creation and download events related to Nmap, which helps us pinpoint **when**, **where**, and **by whom** the tool was introduced.

---

### 🧪 KQL Query — Initial Detection of Nmap
```kql
DeviceFileEvents
| where FileName has "nmap"
| where ActionType in ("FileCreated", "FileDownloaded")
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256



 📌 Findings
User: cyberuser

Files:

nmap.exe

nmap_performance.reg

Nmap - Zenmap GUI.lnk

Timestamps: 19:05:52 — 19:07:01 UTC, 14 July 2025

➡️ Conclusion: nmap — a network scanning tool — was installed or extracted without authorization.

# ✅ Evidence: File creation timeline and user context
🕵️ Next: Confirm execution and usage.

```
<img width="960" height="654" alt="Screenshot 2025-07-20 at 09 31 34" src="https://github.com/user-attachments/assets/4ad3aa75-d288-475b-bd42-490e067ed730" />
```

##  ✅ STEP 2 — Execution Evidence
After detecting the presence of Nmap files, the next step is to confirm whether the tool was executed. Detecting execution is crucial because a tool that simply exists on disk poses less risk than one that was actively used.
We query process execution logs to determine if nmap.exe or its GUI (zenmap) were launched. This helps attribute the activity to a specific user account, confirm installation, and verify that the tool moved from dormant to active — an escalation in severity.
```
kql

DeviceProcessEvents
| where FileName has "nmap" or FileName has "zenmap"
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
📌 Findings
Executable: nmap.exe
```
Path: C:\Program Files (x86)\N...

User: cyberuser

Timestamp: 14 July 2025 — 19:08:08 UTC

Installer: nmap-7.97-setup.exe

Path: C:\Users\cyberuser\Downloads

Timestamp: 14 July 2025 — 19:05:45 UTC

✅ Conclusion: User downloaded and ran the installer, then executed nmap.exe.

![Image Alt](https://github.com/JohnLunnon-cyber/Unauthorized-Nmap-Usage/blob/5bd1cde90fa6eb855a09706ff1f259dafd4fcbd2/Screenshot%202025-07-20%20at%2009.34.43.png)



```

## ✅ STEP 3 — Command Line Analysis
Knowing that a suspicious tool was executed, we now examine how it was used by analyzing the command-line arguments passed during execution.
Command-line flags provide insight into the user’s intent — whether they were performing basic discovery or more advanced enumeration like OS detection, version scanning, or output logging. This helps us assess the level of technical capability, the purpose behind the scan, and the extent of potential impact.

kql
```
DeviceProcessEvents
| where FileName == "nmap.exe"
| where ProcessCommandLine has_any ("-sS", "-A", "-p")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
📌 Findings
Example Command:
```
bash
Copy
Edit
nmap -T4 -A -v -oX C:\Users\CYBERU~1\AppData\Local\Temp\zenmap-lzcrtqu5.xml
Flags:

-T4: Faster/aggressive timing

-A: OS/version detection, script scan, traceroute

-v: Verbose

-oX: Output as XML
```
![Image Alt](https://github.com/JohnLunnon-cyber/Unauthorized-Nmap-Usage/blob/d75f60a3a3537ccaa6089d1c1fc4f0b615dbf14d/Screenshot%202025-07-20%20at%2010.53.05.png)

✅ Conclusion: Advanced scan with host OS/version detection. Output saved locally.

## ✅ STEP 4 — Network Activity Check
To determine the effect of the Nmap execution, we check for outbound network activity generated by the scan. If successful, Nmap would initiate connections to various IP addresses and ports on the network, which should appear in network telemetry.
This step helps validate whether the tool was simply tested, ran ineffectively, or used in an actual reconnaissance attempt. A lack of data can still be valuable — it may indicate local scanning only, firewall blocking, or limitations in logging coverage.

kql
```
DeviceNetworkEvents
| where InitiatingProcessFileName == "nmap.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, LocalPort, InitiatingProcessCommandLine
📌 Result
```
No logs returned
Possible reasons:
Local-only scan.
Firewall blocked traffic.
Telemetry gap.

![Image Alt](https://github.com/JohnLunnon-cyber/Unauthorized-Nmap-Usage/blob/b47b2b2b7514bf80a836c42314d5fc97d3827e8f/Screenshot%202025-07-20%20at%2010.56.37.png)


✅ Next: Broadened query — no results.

### ✅ STEP 5 — Employee & Management Response
After technical confirmation, the incident shifts into the response and policy enforcement phase. We engage with the employee to understand the motivation behind the action — whether it was malicious, negligent, or accidental.
The goal here is to enforce Acceptable Use Policies (AUP), assess user awareness, and determine whether disciplinary or remedial actions are needed. Additionally, we review whether our existing controls (like allow-listing or software restrictions) need improvement to prevent recurrence.
This step ensures accountability, documentation, and organizational learning from the incident.

👥 Meeting with Employee
Discuss: Reason for installing & using nmap.
Reinforce: Acceptable Use Policy (AUP) and security rules.
Assess: Need for training/awareness.
Document: Employee statement & acknowledgement.

🏢 Escalate to Management
Review: Any needed HR/disciplinary action.
Evaluate: Extra controls (application allow-listing, endpoint restrictions).

Update: Policies if needed.

Share: Anonymized lessons learned with wider team.

 ✅ Recommended Actions
Action	Owner	Priority
Conduct employee meeting	IT Security & HR	High
Document findings	IT Security	High
Escalate to management	Security Manager	High
Improve controls	IT & Security	Medium
Share lessons learned	Security Awareness Team	Medium

 ✅ Status
📌 Investigation Complete — Follow-Up Actions In Progress

🔐 End of Report

