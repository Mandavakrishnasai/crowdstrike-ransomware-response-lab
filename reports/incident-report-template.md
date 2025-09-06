## Executive Summary
On <date IST>, Falcon detected ransomware-like activity (EICAR, shadow copy deletion). Falcon auto-contained the host; enrichment/notes captured by the lab responder.

## Timeline (IST)
- hh:mm – EICAR / PowerShell
- hh:mm – vssadmin (Inhibit System Recovery)
- hh:mm – Host contained automatically
- hh:mm – Analyst validated & released

## Impacted Host/User
- Host: MANDAVA
- User: manda

## Indicators
- Processes: powershell.exe, vssadmin.exe
- Paths: C:\Users\Public\...
- Test file: EICAR string

## ATT&CK Mapping
- T1059 Command & Scripting (PowerShell)
- T1490 Inhibit System Recovery (vssadmin)
- T1486 Data Encrypted for Impact (simulated churn)

## Response Actions
- Automated: Falcon containment
- Analyst/Automation: enrichment & notes

## Lessons Learned / Prevention
- Keep ransomware protections enabled (file encryption, filesystem access)
- Maintain auto-containment workflow + release procedure
