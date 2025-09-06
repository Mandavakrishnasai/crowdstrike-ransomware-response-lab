# crowdstrike-falcon-autocontain-lab

Hands-on lab that demonstrates **CrowdStrike Falcon** detection → **automated containment** for ransomware-style behavior.
Windows 11 VM generates safe signals (EICAR + shadow copy tampering).
An Ubuntu 22.04 host runs a small Python responder that polls Falcon APIs and, when appropriate, **contains the endpoint**.
All steps are reproducible and kept inside an isolated lab.

---

## What this shows

* Falcon sensor deployed and reporting from a **Windows 11 VM** (e.g., host `MANDAVA`).
* Detections for:

  * EICAR test file via **PowerShell**.
  * **T1490 – Inhibit System Recovery** using `vssadmin` (shadow copy tampering).
* Python responder that queries Falcon detections and **requests network containment** via API (with basic filtering and cooldown).
* Validation in Falcon UI: **Contained → Released**, plus responder logs.

---

## Architecture

```
                    CrowdStrike Falcon Cloud (OAuth2)
                          ▲          ▲
     /detects (poll)      │          │  contain action
                          │          │
  Windows 11 VM (sensor)  │          │  Ubuntu 22.04 (responder)
  ┌───────────────────────┴─┐     ┌──┴──────────────────────────┐
  │ FalconSensor_Windows    │     │ auto_respond.py (.venv)     │
  │ Safe-RansomSim.ps1      │     │ .env: CS_BASE / CLIENT / SEC│
  │ EICAR & file churn      │     │ Logs to stdout or responder.log
  └─────────────────────────┘     └──────────────────────────────┘
```

---

## Prereqs

* VMware/VirtualBox with:

  * **Windows 10/11 VM** (used: Windows 11)
  * **Ubuntu 22.04** (4–8 GB RAM recommended)
* CrowdStrike Falcon trial (15 days)
* (Optional) VirusTotal API key for enrichment
* **Lab network only** (do not run on production machines)

---

## Quick start

### 1) Install Falcon sensor (Windows 11)

1. Falcon Console → **Host setup & management → Sensor downloads**: get `FalconSensor_Windows.exe` and note your **CID**.
2. Place the EXE somewhere convenient (e.g., `C:\vmshare`), then run (Admin PowerShell):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
$CID = "YOUR-CID-HERE"   # e.g., BFC69985....-3C
$exe = Get-ChildItem -Path "C:\vmshare" -Filter "FalconSensor_Windows*.exe" | Sort LastWriteTime -Desc | Select -First 1
Start-Process $exe.FullName -ArgumentList "/install /quiet /norestart CID=$CID" -Wait
# Verify: services.msc -> CSFalconService = Running
```

In the Falcon console, the host should appear under **Host management**.

---

### 2) Responder (Ubuntu 22.04)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip
mkdir -p ~/falcon-autorespond && cd ~/falcon-autorespond
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip requests python-dotenv
```

Create `.env` (do **not** commit real secrets):

```ini
CS_BASE=https://api.us-2.crowdstrike.com
CS_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CS_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
POLL_SECONDS=60
# optional
VT_APIKEY=
```

Put your `auto_respond.py` in `~/falcon-autorespond/` and run:

```bash
cd ~/falcon-autorespond
./.venv/bin/python -u auto_respond.py
# Expect: "Responder up." then periodic polling
```

*(Optional background mode)*

```bash
nohup ./.venv/bin/python -u auto_respond.py > responder.log 2>&1 &
tail -n 50 -f responder.log
```

---

### 3) Generate safe detections (Windows 11)

**A) EICAR (benign AV test string)**

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
$e='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$dst="C:\Users\Public\eicar_$((Get-Date).ToString('HHmmss')).com"
Set-Content -Path $dst -Value $e -NoNewline
Get-Content $dst > $null
```

**B) Ransomware-like file churn (confined to a test folder)**

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
$F="C:\Lab\RansomTest\work"; Remove-Item -Recurse -Force $F -EA SilentlyContinue
New-Item -ItemType Directory -Force -Path $F | Out-Null
1..400 | % { Set-Content -Path (Join-Path $F ("file_{0:D4}.txt" -f $_)) -Value ("x"*4096) }
$end=(Get-Date).AddMinutes(2)
while((Get-Date) -lt $end){
  Get-ChildItem $F -File | % {
    $b=New-Object byte[] 4096; (New-Object System.Random).NextBytes($b)
    [IO.File]::WriteAllBytes($_.FullName,$b)
    Rename-Item $_.FullName ($_.BaseName + ".locked") -EA SilentlyContinue
  }
}
"Simulation done"
```

**C) (Optional) T1490 shadow copy tampering**
`vssadmin delete shadows /all /quiet` is disruptive (deletes restore points). If you want to demo it, **snapshot the VM first** and run from an elevated prompt. It commonly triggers **High** severity detections under **Impact → Inhibit System Recovery (T1490)**.

---

## Validate

* **Falcon → Endpoint detections**

  * `powershell.exe` wrote EICAR (Informational/Low-Medium).
  * `vssadmin.exe` → **Impact via Inhibit System Recovery (T1490)** (High).
* **Falcon → Host management**

  * Host shows **Contained** after response (either policy or responder).
  * Use **Actions → Release containment** to restore network.
* **Responder output**

  * `Responder up.`
  * Lines like `id=<detect_id> host=<hostname> suspicious=True`
  * `contain -> 202` on successful isolation request.

---

## Minimal API scopes (Falcon OAuth2)

* **Detections: Read** (queries + summaries)
* **Hosts/Devices: Read**
* **Containment: Write** (to isolate hosts)

If your trial doesn’t permit isolation, keep the responder as **logging/enrichment** only.

---

## ATT\&CK mapping

* **T1059** — Command & Scripting Interpreter (PowerShell)
* **T1486** — Data Encrypted for Impact (simulated via rename/overwrite churn)
* **T1490** — Inhibit System Recovery (`vssadmin` / shadow copies)

---

## Troubleshooting

* No detections? Ensure **CSFalconService** is running; re-run a simulator; confirm prevention/visibility policy.
* API 401/403? Check **CS\_BASE** (e.g., `https://api.us-2.crowdstrike.com`) and client scopes; rotate secret if needed.
* Scripts blocked? Use `Set-ExecutionPolicy -Scope Process Bypass -Force`.
* Background logs: `tail -n 50 -f ~/falcon-autorespond/responder.log`.

---

## Safety

* **No real malware**. EICAR is an industry-standard benign string.
* File-churn script stays in a dedicated test folder.
* Keep everything inside the lab VMs.

---

## Evidence (suggested)

* Detections list (EICAR + T1490)
* Detection detail for `vssadmin` (shows tactic/technique)
* Host **Contained** and **Released** screenshots
* Responder log snippet with `contain -> 202`

---

## License

MIT (or your preference).
Do **not** commit real API credentials—use `.env.example` with placeholders.
