#!/usr/bin/env python3
import os, sys, json, subprocess, time
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("PORT", 8080))
LOG_DIR = "/home/node/.clawsec"
PID_FILE = f"{LOG_DIR}/clawsec.pid"
THREATS_FILE = f"{LOG_DIR}/threats.jsonl"
os.makedirs(LOG_DIR, exist_ok=True)

def start_clawsec():
    if os.path.exists(PID_FILE): return
    proc = subprocess.Popen([sys.executable, "clawsec-monitor.py", "start"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/app")
    with open(PID_FILE, "w") as f: f.write(str(proc.pid))
    time.sleep(2)

def stop_clawsec():
    if not os.path.exists(PID_FILE): return
    subprocess.run([sys.executable, "clawsec-monitor.py", "stop"])
    os.remove(PID_FILE)

def is_running(): return os.path.exists(PID_FILE)

def get_status():
    result = subprocess.run([sys.executable, "clawsec-monitor.py", "status"], capture_output=True, text=True, cwd="/app")
    return result.stdout or result.stderr

def get_threats(limit=10):
    if not os.path.exists(THREATS_FILE): return []
    return [json.loads(l) for l in open(THREATS_FILE).readlines()[-limit:] if l.strip()]

class APIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/status", "/status/"]:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"status": "running", "output": get_status()}).encode())
        elif self.path.startswith("/threats"):
            limit = 10
            if "?" in self.path:
                try: limit = int(self.path.split("?")[1].split("=")[1])
                except: pass
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(get_threats(limit)).encode())
        elif self.path in ["/health", "/health/"]:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"healthy": is_running()}).encode())
        elif self.path in ["/", ""]:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"service": "ClawSec", "endpoints": ["/health", "/status", "/threats"]}).encode())
        else: self.send_response(404); self.end_headers()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python3 clawsec-api.py [start|stop|status|threats]"); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "start": start_clawsec(); HTTPServer(("0.0.0.0", PORT), APIHandler).serve_forever()
    elif cmd == "stop": stop_clawsec()
    elif cmd == "status": print(get_status())
    elif cmd == "threats": print(json.dumps(get_threats(), indent=2))
