[README_lab3.md](https://github.com/user-attachments/files/28820316/README_lab3.md)
# Splunk-SIEM-Log-Analysis
A hands-on lab demonstrating Deploying Splunk and ingest real log data, Writing SPL searches to find threats, Building a live security dashboard, Creating automated detection alerts and Conduct basic threat hunting.
# Lab 3 — Splunk SIEM & Log Analysis

![Certification](https://img.shields.io/badge/CompTIA-Security%2B-blue) ![Certification](https://img.shields.io/badge/CompTIA-CySA%2B-blue) ![Certification](https://img.shields.io/badge/Splunk-Core%20Certified%20User-informational) ![Cost](https://img.shields.io/badge/Cost-%240-brightgreen) ![Duration](https://img.shields.io/badge/Duration-4--6%20hours-yellow) ![Tool](https://img.shields.io/badge/Tool-Splunk%20Enterprise-black)

**Stack:** Splunk Enterprise · Azure Ubuntu VM · Windows Server (Lab 1)  
**Roles:** SOC Analyst Tier 1–3 · Security Engineer · Incident Responder · Cloud Security Engineer

---

## About this lab

A medium-sized organisation generates millions of log events every day — Windows Event Logs from workstations, authentication logs from Active Directory, firewall logs, web server access logs, cloud resource logs. Without a SIEM, those logs sit in separate systems and nobody can search across them, correlate events, or identify patterns that signal an attack in progress.

Splunk is the most widely deployed commercial SIEM. Learning it in a free lab environment gives you a concrete, demonstrable skill that appears on job descriptions for almost every security operations role. The mental model you build here transfers directly to Microsoft Sentinel, AWS Security Hub, and Google Chronicle.

---

## Architecture — How Splunk receives and processes logs

```
  ┌─────────────────────── Azure Virtual Network ────────────────────────────┐
  │                                                                           │
  │  ┌──────────────────────────┐                                            │
  │  │   Windows Server VM      │  ← Active Directory from Lab 1             │
  │  │   Security/System/App    │                                            │
  │  └────────────┬─────────────┘                                            │
  │               │ Event Logs                                                │
  │               ▼                                                           │
  │  ┌──────────────────────────┐                                            │
  │  │   Universal Forwarder    │  ← Lightweight agent on Windows VM         │
  │  │   inputs.conf · port 9997│    Compresses, encrypts, forwards          │
  │  └────────────┬─────────────┘                                            │
  │               │ encrypted · port 9997                                     │
  │               ▼                                                           │
  │  ┌─────────────────────────────────────────────────────────────────────┐ │
  │  │  Ubuntu VM — Splunk Enterprise                                      │ │
  │  │                                                                     │ │
  │  │  ┌──────────────────────┐      ┌──────────────────────┐            │ │
  │  │  │   Splunk indexer     │─────►│   Splunk web UI      │            │ │
  │  │  │   windows_logs index │      │   Search & reporting  │            │ │
  │  │  │   port 9997 receiver │      │   port 8000           │            │ │
  │  │  └──────────────────────┘      └──────────┬───────────┘            │ │
  │  └─────────────────────────────────────────── │ ──────────────────────┘ │
  └──────────────────────────────────────────────  │ ─────────────────────────┘
                                                   │ port 8000
                                                   ▼
                                       ┌───────────────────────┐
                                       │   Analyst browser     │
                                       │   Dashboards · Alerts │
                                       │   SPL searches        │
                                       └───────────────────────┘
```

**How the flow works:**  
The Universal Forwarder agent runs on your Windows Server VM, monitors the Security, System, and Application event logs via `inputs.conf`, and streams them over port 9997 to the Splunk indexer running on a separate Ubuntu VM. The indexer stores events in a named index (`windows_logs`). The Splunk web UI on port 8000 is where you write SPL searches, build dashboards, and configure automated alerts — all against the indexed data.

---

## What you will be able to do after completing this lab

| Skill | Real-world application |
|---|---|
| Deploy Splunk and configure a data input | Every Splunk deployment starts with getting data in — the Universal Forwarder is how most enterprise environments feed logs to Splunk |
| Navigate the Splunk interface | Search, dashboards, alerts, reports — understanding the layout is table stakes for any SOC role |
| Write SPL searches | SPL is how you ask Splunk questions — the skill that separates analysts who find threats from analysts who stare at dashboards |
| Build security dashboards | Visualising login failures, lockouts, and after-hours activity at a glance |
| Identify failed login attempts | Distinguishing normal user error from a brute force or password spray attack |
| Build an automated alert | Splunk fires an alert when conditions you define are met — this is how real SOC detection works |
| Search for account lockout events | A trail of lockout events can indicate a password spray attack in progress |

---

## Prerequisites

- Lab 1 complete (Windows Server VM with Active Directory running in Azure) — or Splunk's built-in sample data as a substitute
- An Azure account (free tier eligible)
- Basic comfort with a Linux terminal (SSH commands)

---

## Key concepts

Read these before starting. They explain the vocabulary you will see throughout every step.

### What is a SIEM?
SIEM stands for Security Information and Event Management. A SIEM collects log data from across your entire environment and makes it searchable in one place. Its two core jobs are correlation (connecting events across systems to find patterns no single system would reveal alone) and alerting (automatically notifying analysts when suspicious conditions are met).

### What is SPL?
SPL (Splunk Processing Language) is the query language you use to ask Splunk questions. It works as a pipeline — you start with a search, then pipe results through commands that filter, transform, and visualise. Every SPL search follows this pattern:

```
index=windows_logs EventCode=4625
| stats count by Account_Name
| sort -count
```

Find the events → shape the results. You do not need to know SPL before starting — every search in this lab is explained line by line.

### What is a Splunk index?
An index is a named storage bucket where events are kept, similar to a database table. When logs arrive, they are stored in an index. When you search, you specify `index=name`. In this lab you create one index called `windows_logs`.

### What is the Universal Forwarder?
A lightweight free agent that monitors Windows Event Logs and log files, then compresses, encrypts, and forwards the data to your Splunk indexer over port 9997. It is designed to run invisibly in the background on production servers with minimal CPU and RAM impact.

### What are Windows Event IDs?
Windows records every system activity as numbered events in the Event Log. The three you will use constantly in security work:

| EventCode | Meaning | Security relevance |
|---|---|---|
| 4624 | Successful logon | Baseline — who is logging in and how |
| 4625 | Failed logon | Spike = brute force; spread across many accounts = password spray |
| 4740 | Account locked out | Trail of lockouts often indicates automated attack in progress |

### What is inputs.conf?
A configuration file on the Windows VM that tells the Universal Forwarder which logs to collect and forward. Each section in square brackets defines one data source. You edit this file once during setup.

---

## Step 1 — Get Splunk free

Splunk Enterprise is free to download. You receive a 60-day full trial, after which it converts automatically to the free licence. The free licence allows up to 500MB per day of data indexing — more than enough for this lab.

> **Protecting your privacy:** Splunk requires a registration form to download. Use a temporary email address rather than your personal one.
> 1. Go to [temp-mail.org](https://temp-mail.org/en/) — a disposable address is generated automatically
> 2. Paste it into the Splunk registration form at [splunk.com/download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
> 3. Fill remaining fields (name, company, title, phone) with any placeholder values — they are not verified
> 4. Check the temp-mail inbox for the confirmation email and click the link

Download **Splunk Enterprise** for Linux (the Ubuntu VM you will create next). Do not select Splunk Cloud (hosted SaaS) or Splunk SOAR.

---

## Step 2 — Deploy the Ubuntu VM in Azure

Running Splunk on an Azure VM keeps it running when your laptop is closed and lets your Active Directory VM (Lab 1) send logs over the internal Azure network.

| VM setting | Value |
|---|---|
| OS | Ubuntu 22.04 LTS (free tier eligible) |
| Size | Standard_B2s (2 vCPU, 4GB RAM minimum) |
| Disk | 30GB minimum |
| Inbound NSG port 8000 | Your IP address only (Splunk web UI) |
| Inbound NSG port 9997 | VNet address range only, e.g. 10.0.0.0/16 (forwarder input — not public internet) |
| Inbound NSG port 22 | Your IP address only (SSH) |

### Connecting via SSH

**macOS / Linux** — SSH is built in. Open Terminal and run:
```bash
ssh yourusername@YOUR_VM_PUBLIC_IP
# Type yes when prompted about the host fingerprint, then enter your password
```

**Windows** — Install [PuTTY](https://www.putty.org) first (free, download the 64-bit `.msi` installer). Open PuTTY, enter the VM public IP in the Host Name field, port 22, connection type SSH, then click Open. When the terminal appears, enter your VM admin username and password. Note: password characters do not appear on screen in PuTTY — this is normal Linux behaviour.

---

## Step 3 — Install Splunk on Ubuntu

SSH into your Ubuntu VM and run the following:

```bash
# Download Splunk Enterprise
# NOTE: Splunk updates the URL with every release. If this returns a 404,
# log into splunk.com → Free Trials & Downloads → Linux .deb → copy the current wget command.
wget -O splunk-linux-amd64.deb \
  "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"

# Install the package
sudo dpkg -i splunk-linux-amd64.deb

# Start Splunk and accept the licence
# You will be prompted to set your admin username and password here
sudo /opt/splunk/bin/splunk start --accept-license

# Enable Splunk to start automatically on VM reboot
sudo /opt/splunk/bin/splunk enable boot-start
```

Open the web UI in your browser:
```
http://<YOUR_UBUNTU_VM_PUBLIC_IP>:8000
```

---

## Step 4 — Configure data inputs

### Part A — Enable receiving in Splunk

Before installing the forwarder, tell Splunk to listen for incoming data.

1. Log into the Splunk web UI at `http://your-vm-ip:8000`
2. Click **Settings** → **Forwarding and Receiving**
3. Click **Configure Receiving** → **New Receiving Port** → enter `9997` → **Save**
4. Click **Settings** → **Indexes** → **Create New Index** → name it `windows_logs` → **Save**

### Part B — Install the Universal Forwarder on Windows Server

Do this on your **Windows Server VM from Lab 1**, not the Ubuntu VM.

1. On the Windows Server VM, go to [splunk.com/download/universal-forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html)
2. Download the **Windows 64-bit** installer
3. Run the installer:
   - Deployment Server: enter your Ubuntu VM's **private IP** and port `8089`
   - Receiving Indexer: enter your Ubuntu VM's **private IP** and port `9997`
4. Complete installation with default settings

### Part C — Configure inputs.conf

This file tells the forwarder exactly which Windows Event Logs to collect. On the Windows Server VM, navigate to this path in Windows Explorer:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\
```

If the `local` folder does not exist, create it. Open Notepad as Administrator and save the file as `inputs.conf` in that location with the following contents:

```ini
[WinEventLog://Security]
# Authentication events — logins, failures, lockouts
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1

[WinEventLog://System]
# OS-level events — service starts/stops, driver failures
disabled = 0

[WinEventLog://Application]
# Events from installed applications
disabled = 0
```

After saving, restart the forwarder to apply the changes. Run this in PowerShell as Administrator on the Windows Server VM:

```powershell
Restart-Service SplunkForwarder
```

> **No Lab 1 VM yet?** Splunk ships with built-in sample data. Go to Search → Data Summary to find sample indexes. You can complete most of the search exercises below using sample data while you build out Lab 1.

---

## Step 5 — Essential SPL searches

All searches are typed into the search bar at the top of the **Search & Reporting** app. Select a time range using the picker on the right side of the search bar.

### Confirm data is flowing

```spl
index=windows_logs | head 100
```

If this returns results, your forwarder is working. If it returns nothing, verify the `SplunkForwarder` service is running on the Windows VM.

---

### Find failed login attempts (EventCode 4625)

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name
| sort -count
```

A count of 5 or more for one account in a short window is a possible brute force indicator. Accounts that do not exist in Active Directory indicate enumeration.

---

### Find successful logins (EventCode 4624)

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name, Logon_Type
| sort -count
```

| Logon_Type | Meaning |
|---|---|
| 2 | Interactive — someone at the keyboard |
| 3 | Network — accessing a file share |
| 5 | Service account — automated, usually expected |
| 10 | Remote interactive — RDP session |

---

### Find account lockout events (EventCode 4740)

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4740
| table _time, Account_Name, Caller_Computer_Name
| sort -_time
```

Multiple lockouts for the same account point to brute force. Lockouts spread across many accounts suggest a password spray attack.

---

### Top 10 failed login usernames — threat hunting

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h
| stats count as failures by Account_Name
| sort -failures
| head 10
```

Accounts with 20+ failures in 24 hours warrant investigation. Non-existent usernames indicate account enumeration.

---

### Detect after-hours logins

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, Account_Name, Workstation_Name, Logon_Type
| sort -_time
```

Service account logins (Type 5) outside business hours are normal. Interactive logins (Type 2 or 10) from regular users after hours warrant review.

---

## Step 6 — Build a security dashboard

Dashboards give you a permanent view of your security posture without running searches manually.

1. Click **Dashboards** in the top navigation → **Create New Dashboard**
2. Name it `Windows Security Overview` → **Create Dashboard**
3. Click **Add Panel** for each panel below:

| Panel name | Search | Visualisation |
|---|---|---|
| Failed logins — last 24h | EventCode=4625 with `stats count by Account_Name` | Bar chart |
| Account lockouts — last 7d | EventCode=4740 with `table` output | Events list |
| Login activity over time | EventCode=4624 with `timechart count` | Line chart |
| Top source workstations — after hours | After-hours search with `stats count by Workstation_Name` | Column chart |

For each panel: select **New Search**, paste the relevant search from Step 5, choose the visualisation type, and save.

---

## Step 7 — Create an automated alert

Alerts automate detection. Splunk runs a search on a schedule and notifies you when conditions are met — rather than waiting for a human to notice.

First, run this search to confirm it works:

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count as failures by Account_Name
| where failures > 10
```

Then save it as an alert:

1. Click **Save As** → **Alert**
2. Name: `Potential Brute Force — High Failure Count`
3. Alert type: `Scheduled`
4. Run every: `15 minutes`
5. Trigger condition: `Number of Results is greater than 0`
6. Trigger actions: `Add to Triggered Alerts`
7. Click **Save**

> Setting the threshold at 10 failures is a starting point. In a real environment you tune this threshold based on how many false positives you observe over time. An alert that fires too broadly causes alert fatigue. An alert set too narrow misses real threats.

---

## Verification checklist

| Check | How to verify |
|---|---|
| Data is flowing into Splunk | Run `index=windows_logs \| head 10` — should return recent events |
| Failed login search works | Run the EventCode=4625 search. If no results, intentionally type the wrong password on the Windows VM a few times, then search again |
| Dashboard displays data | Windows Security Overview shows populated panels |
| Alert is active | Settings → Searches, Reports, and Alerts — your alert appears as Enabled |

---

## How this applies to cloud environments

| Splunk skill | Cloud equivalent |
|---|---|
| Universal Forwarder collecting Windows events | Azure Monitor Agent · AWS CloudWatch agent |
| Indexing data into named buckets | Log Analytics workspace tables · CloudWatch Log Groups |
| SPL `stats count by Account_Name` | KQL `summarize count() by AccountName` in Microsoft Sentinel |
| Alert on failure threshold | Sentinel Scheduled Query Rule · AWS GuardDuty finding |
| Building dashboards | Azure Workbooks · CloudWatch Dashboards |
| Investigating EventCode 4625 | Sentinel Sign-in logs · AWS CloudTrail `ConsoleLogin` events |

---

## Portfolio artefacts from this lab

Take screenshots of the following and include them in this repo alongside a short written summary of what each one shows:

| Artefact | What to capture |
|---|---|
| Dashboard screenshot | Windows Security Overview with all four panels populated |
| Alert configuration | The brute force alert settings page showing schedule and trigger |
| SPL search export | Save the after-hours logins search as a Report and export it |
| Findings summary | One paragraph describing what you found in the logs and what it would mean in a real environment |

---

## Resources

- [Splunk documentation](https://docs.splunk.com/Documentation/Splunk)
- [Splunk SPL quick reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands)
- [Windows Security Event IDs reference — Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [CompTIA CySA+ certification](https://www.comptia.org/certifications/cybersecurity-analyst)
- [Splunk Core Certified User exam](https://www.splunk.com/en_us/training/certification-track/splunk-core-certified-user.html)
