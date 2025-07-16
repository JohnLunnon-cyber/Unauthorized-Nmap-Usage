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
