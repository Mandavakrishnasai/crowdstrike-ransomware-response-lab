import os, time, json, traceback, requests, paramiko
from datetime import datetime, timezone
from dotenv import load_dotenv

def log(m): print(datetime.now(timezone.utc).isoformat(), m, flush=True)

load_dotenv()
CS_BASE=os.getenv("CS_BASE","https://api.us-2.crowdstrike.com").rstrip("/")
CS_ID=os.getenv("CS_CLIENT_ID"); CS_SEC=os.getenv("CS_CLIENT_SECRET")
VT_KEY=os.getenv("VT_APIKEY",""); POLL=int(os.getenv("POLL_SECONDS","60"))
WIN_HOST=os.getenv("WIN_SSH_HOST",""); WIN_USER=os.getenv("WIN_SSH_USER",""); WIN_PASS=os.getenv("WIN_SSH_PASS","")
STATE_FILE="state.json"

def save_state(s): open(STATE_FILE,"w").write(json.dumps(s))
def load_state():
    try: return json.load(open(STATE_FILE))
    except: return {"seen_ids":[]}

def token():
    r=requests.post(f"{CS_BASE}/oauth2/token",
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        data={"client_id":CS_ID,"client_secret":CS_SEC,"grant_type":"client_credentials"},timeout=30)
    r.raise_for_status(); return r.json()["access_token"]

def list_detect_ids(tok,limit=5):
    r=requests.get(f"{CS_BASE}/detects/queries/detects/v1",
        headers={"Authorization":f"Bearer {tok}"},
        params={"limit":str(limit),"sort":"last_behavior|desc"},timeout=30)
    r.raise_for_status(); return r.json().get("resources",[]) or []

def detect_summaries(tok,ids):
    if not ids: return []
    r=requests.post(f"{CS_BASE}/detects/entities/summaries/GET/v1",
        headers={"Authorization":f"Bearer {tok}","Content-Type":"application/json"},
        json={"ids":ids}, timeout=30)
    r.raise_for_status(); return r.json().get("resources",[]) or []

def vt_lookup(sha):
    if not VT_KEY: return {"vt_skipped":True}
    r=requests.get(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey":VT_KEY}, timeout=30)
    if r.status_code==404: return {"vt_found":False}
    r.raise_for_status(); d=r.json(); s=(d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{}) or {})
    return {"vt_found":True,"malicious":s.get("malicious",0),"suspicious":s.get("suspicious",0),"raw":d}

def contain(tok,device_ids):
    r=requests.post(f"{CS_BASE}/devices/entities/devices-actions/v2",
        headers={"Authorization":f"Bearer {tok}","Content-Type":"application/json"},
        params={"action_name":"contain"}, json={"ids":device_ids}, timeout=30)
    return r.status_code, (r.json() if r.content else {})

def ssh_fallback():
    if not (WIN_HOST and WIN_USER and WIN_PASS): return False,"SSH creds missing"
    cmd=r'''powershell -NoProfile -NonInteractive -Command "New-NetFirewallRule -DisplayName 'Contain-Lab' -Direction Outbound -Action Block -Profile Any -Enabled True"'''
    ssh=paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(WIN_HOST,username=WIN_USER,password=WIN_PASS,timeout=15,look_for_keys=False,allow_agent=False)
    _,o,e=ssh.exec_command(cmd); rc=o.channel.recv_exit_status(); out=o.read().decode(); err=e.read().decode(); ssh.close()
    return (rc==0), f"rc={rc} out={out} err={err}"

def main():
    st=load_state(); log("Responder up.")
    while True:
        try:
            tok=token(); ids=list_detect_ids(tok,5); new=[i for i in ids if i not in st["seen_ids"]]
            if not new: log("No new detections.")
            for det in detect_summaries(tok,new):
                det_id=det.get("detection_id") or det.get("id") or "unknown"
                dev=det.get("device",{}) or {}; device_id=dev.get("device_id") or dev.get("id"); host=dev.get("hostname") or dev.get("host_name")
                sha=None
                for b in (det.get("behaviors",[]) or []): sha=b.get("sha256") or sha
                sev=(det.get("max_severity_displayname") or det.get("severity","")).lower()
                vt={"vt_skipped":True}
                if sha:
                    try: vt=vt_lookup(sha)
                    except Exception as e: vt={"error":str(e)}
                suspicious = (isinstance(vt,dict) and vt.get("vt_found") and vt.get("malicious",0)>0) or (sev in ("high","critical","5","4"))
                log(f"[{det_id}] host={host} device={device_id} sha={sha} suspicious={suspicious}")
                if suspicious and device_id:
                    code,resp=contain(tok,[device_id]); log(f"[{det_id}] isolate -> {code} {resp}")
                    if code==403:
                        ok,msg=ssh_fallback(); log(f"[{det_id}] fallback firewall -> ok={ok} {msg}")
                st["seen_ids"].append(det_id); save_state(st)
        except Exception as e:
            log(f"Error: {e}\n{traceback.format_exc()}")
        time.sleep(int(os.getenv("POLL_SECONDS","60")))

if __name__=="__main__": main()
