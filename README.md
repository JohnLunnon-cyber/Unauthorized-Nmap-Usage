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

### 🔍 Initial Query

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

✅ Evidence: File creation timeline and user context
🕵️ Next: Confirm execution and usage.


