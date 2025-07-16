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

## 🔍 Initial Query

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

## ✅ Evidence: File creation timeline and user context
🕵️ Next: Confirm execution and usage.

##  ✅ STEP 2 — Execution Evidence
kql
Copy
Edit
DeviceProcessEvents
| where FileName has "nmap" or FileName has "zenmap"
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
📌 Findings
Executable: nmap.exe

Path: C:\Program Files (x86)\N...

User: cyberuser

Timestamp: 14 July 2025 — 19:08:08 UTC

Installer: nmap-7.97-setup.exe

Path: C:\Users\cyberuser\Downloads

Timestamp: 14 July 2025 — 19:05:45 UTC

✅ Conclusion: User downloaded and ran the installer, then executed nmap.exe.

## ✅ STEP 3 — Command Line Analysis
kql
Copy
Edit
DeviceProcessEvents
| where FileName == "nmap.exe"
| where ProcessCommandLine has_any ("-sS", "-A", "-p")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
📌 Findings
Example Command:

bash
Copy
Edit
nmap -T4 -A -v -oX C:\Users\CYBERU~1\AppData\Local\Temp\zenmap-lzcrtqu5.xml
Flags:

-T4: Faster/aggressive timing

-A: OS/version detection, script scan, traceroute

-v: Verbose

-oX: Output as XML

✅ Conclusion: Advanced scan with host OS/version detection. Output saved locally.

## ✅ STEP 4 — Network Activity Check
kql
Copy
Edit
DeviceNetworkEvents
| where InitiatingProcessFileName == "nmap.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, LocalPort, InitiatingProcessCommandLine
📌 Result
No logs returned

Possible reasons:

Local-only scan.

Firewall blocked traffic.

Telemetry gap.

✅ Next: Broadened query — no results.

### ✅ STEP 5 — Employee & Management Response
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

