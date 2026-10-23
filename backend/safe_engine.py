import asyncio
import json
import logging
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("NetSentry")

# ─────────────────────────────────────────────
# SAFETY-CRITICAL CONSTANTS  (do not change)
# ─────────────────────────────────────────────
ISOLATED_PORT         = 9999   # Only port ever touched by iptables rules
SYN_FLOOD_THRESHOLD   = 15     # SYN packets per rolling window to trigger block
BRUTEFORCE_THRESHOLD  = 5      # HTTP POST requests per rolling window
DECAY_WINDOW_SECS     = 2.0    # Rolling window size in seconds
BLOCK_TTL_SECS        = 20     # Auto-expiry time for blocked IPs
WS_BROADCAST_INTERVAL = 1.0    # WebSocket push cadence
MAX_INCIDENT_LOG      = 50

# ─────────────────────────────────────────────
# Shared State
# ─────────────────────────────────────────────
_lock         = threading.Lock()
_syn_events   = defaultdict(deque)   # ip -> deque of timestamps
_post_events  = defaultdict(deque)
_blocked      = {}                   # ip -> expiry timestamp
_incidents    = deque(maxlen=MAX_INCIDENT_LOG)
_ip_metrics   = defaultdict(lambda: {"syn_rate": 0, "post_rate": 0, "pps": 0, "last_seen": None})
_timeline     = deque(maxlen=20)
_iptables_ok  = True


# ─────────────────────────────────────────────
# Firewall Helper  (always targets port 9999)
# ─────────────────────────────────────────────
def _safe_iptables(action: str, ip: str) -> bool:
    global _iptables_ok
    cmd = ["sudo", "iptables"] + action.split() + [
        "-p", "tcp", "--dport", str(ISOLATED_PORT), "-s", ip, "-j", "DROP"
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            log.warning("iptables failed for %s: %s", ip, r.stderr.strip())
            _iptables_ok = False
            return False
        _iptables_ok = True
        return True
    except Exception as exc:
        log.warning("iptables unavailable (%s) – in-memory blocklist only", exc)
        _iptables_ok = False
        return False


def block_ip(ip: str, reason: str) -> None:
    with _lock:
        if ip in _blocked:
            return
        _blocked[ip] = time.time() + BLOCK_TTL_SECS
        _incidents.appendleft({
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "ip": ip, "reason": reason, "action": "BLOCKED",
        })
        log.info("BLOCKED %s – %s", ip, reason)
    _safe_iptables("-I INPUT 1", ip)


def unban_ip(ip: str) -> bool:
    with _lock:
        if ip not in _blocked:
            return False
        del _blocked[ip]
        _incidents.appendleft({
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "ip": ip, "reason": "Manual unban via API", "action": "UNBANNED",
        })
        log.info("UNBANNED %s (manual)", ip)
    _safe_iptables("-D INPUT", ip)
    return True


# ─────────────────────────────────────────────
# Background Sweeper  (auto-expires rules)
# ─────────────────────────────────────────────
def _sweeper_thread() -> None:
    while True:
        time.sleep(1)
        now     = time.time()
        expired = []
        with _lock:
            for ip, expiry in list(_blocked.items()):
                if now >= expiry:
                    expired.append(ip)
                    del _blocked[ip]
                    _incidents.appendleft({
                        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                        "ip": ip, "reason": "TTL expired (20s)", "action": "UNBLOCKED",
                    })
                    log.info("AUTO-UNBLOCKED %s", ip)
        for ip in expired:
            _safe_iptables("-D INPUT", ip)


# ─────────────────────────────────────────────
# Detection Engine
# ─────────────────────────────────────────────
def _purge_old(dq: deque, now: float) -> None:
    while dq and now - dq[0] > DECAY_WINDOW_SECS:
        dq.popleft()


def process_packet(ip_src: str, syn: str, ack: str, http_method: str) -> None:
    if not ip_src:
        return
    now     = time.time()
    is_syn  = syn.strip() == "1" and ack.strip() == "0"
    is_post = http_method.strip().upper() == "POST"
    with _lock:
        if is_syn:
            dq = _syn_events[ip_src]
            dq.append(now)
            _purge_old(dq, now)
            rate = len(dq)
            _ip_metrics[ip_src]["syn_rate"]  = rate
            _ip_metrics[ip_src]["last_seen"] = now
            if rate > SYN_FLOOD_THRESHOLD and ip_src not in _blocked:
                reason = "SYN Flood ({} SYNs / {}s)".format(rate, DECAY_WINDOW_SECS)
                threading.Thread(target=block_ip, args=(ip_src, reason), daemon=True).start()
        if is_post:
            dq = _post_events[ip_src]
            dq.append(now)
            _purge_old(dq, now)
            rate = len(dq)
            _ip_metrics[ip_src]["post_rate"] = rate
            _ip_metrics[ip_src]["last_seen"] = now
            if rate > BRUTEFORCE_THRESHOLD and ip_src not in _blocked:
                reason = "HTTP Brute-Force ({} POSTs / {}s)".format(rate, DECAY_WINDOW_SECS)
                threading.Thread(target=block_ip, args=(ip_src, reason), daemon=True).start()
        _ip_metrics[ip_src]["pps"] = _ip_metrics[ip_src].get("pps", 0) + 1


# ─────────────────────────────────────────────
# tshark Subprocess Listener
# ─────────────────────────────────────────────
def _tshark_listener() -> None:
    cmd = [
        "tshark", "-i", "lo", "-l",
        "-f", "tcp port 9999",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "http.request.method",
        "-E", "separator=,",
    ]
    backoff = 2
    while True:
        log.info("Starting tshark on lo filtered to tcp/9999")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
            for raw in proc.stdout:
                parts = (raw.strip() + ",,,").split(",")
                process_packet(parts[0], parts[1], parts[2], parts[3])
            proc.wait()
            log.warning("tshark exited (code %s) – restarting in %ds", proc.returncode, backoff)
        except FileNotFoundError:
            log.error("tshark not found. Install Wireshark/tshark. Retrying in %ds", backoff)
        except Exception as exc:
            log.error("tshark error: %s – retrying in %ds", exc, backoff)
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)


# ─────────────────────────────────────────────
# Timeline Aggregator
# ─────────────────────────────────────────────
def _timeline_aggregator() -> None:
    while True:
        time.sleep(1)
        with _lock:
            ts   = sum(m["syn_rate"]  for m in _ip_metrics.values())
            tp   = sum(m["post_rate"] for m in _ip_metrics.values())
            tpps = sum(m["pps"]       for m in _ip_metrics.values())
            for m in _ip_metrics.values():
                m["pps"] = 0
            _timeline.append({
                "time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "syn_rate": ts, "post_rate": tp, "total_pps": tpps,
            })


# ─────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────
app = FastAPI(title="NetSentry", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    for fn, name in [
        (_tshark_listener,     "tshark-listener"),
        (_sweeper_thread,      "rule-sweeper"),
        (_timeline_aggregator, "timeline-agg"),
    ]:
        t = threading.Thread(target=fn, daemon=True, name=name)
        t.start()
        log.info("Started thread: %s", name)


class UnbanRequest(BaseModel):
    ip: str


@app.post("/api/unban")
def api_unban(req: UnbanRequest):
    return {"success": unban_ip(req.ip), "ip": req.ip}


@app.get("/api/health")
def api_health():
    with _lock:
        return {
            "status": "ok",
            "blocked_count": len(_blocked),
            "incident_count": len(_incidents),
            "iptables_available": _iptables_ok,
            "isolated_port": ISOLATED_PORT,
        }


@app.post("/api/simulate/syn")
def simulate_syn():
    fake_ip = "127.42.0.1"
    for _ in range(20):
        process_packet(fake_ip, "1", "0", "")
    return {"status": "simulated", "ip": fake_ip, "packets": 20, "type": "SYN Flood"}


@app.post("/api/simulate/bruteforce")
def simulate_bruteforce():
    fake_ip = "127.42.0.2"
    for _ in range(8):
        process_packet(fake_ip, "0", "1", "POST")
    return {"status": "simulated", "ip": fake_ip, "packets": 8, "type": "Brute-Force"}


@app.websocket("/ws/traffic")
async def ws_traffic(websocket: WebSocket):
    await websocket.accept()
    log.info("WS client connected: %s", websocket.client)
    try:
        while True:
            with _lock:
                blocked_snap  = {
                    ip: {"expiry": e, "ttl_remaining": max(0, int(e - time.time()))}
                    for ip, e in _blocked.items()
                }
                incident_snap = list(_incidents)[:8]
                metrics_snap  = {k: dict(v) for k, v in _ip_metrics.items()}
                timeline_snap = list(_timeline)
            payload = {
                "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "blocked": blocked_snap,
                "incidents": incident_snap,
                "ip_metrics": metrics_snap,
                "timeline": timeline_snap,
                "iptables_ok": _iptables_ok,
                "isolated_port": ISOLATED_PORT,
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(WS_BROADCAST_INTERVAL)
    except WebSocketDisconnect:
        log.info("WS client disconnected")
    except Exception as exc:
        log.error("WS error: %s", exc)


if __name__ == "__main__":
    uvicorn.run("safe_engine:app", host="0.0.0.0", port=8000, reload=False)
