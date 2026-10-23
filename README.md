# NetSentry

## Real-Time L4/L7 Anomaly Detection & Automated Firewall Mitigator

A lightweight prototype for Computer Networks projects.
Wireshark/tshark-powered backend (FastAPI) + Next.js dashboard.

---

## Safety Design

| Guarantee | Implementation |
|-----------|---------------|
| Port Isolation | All capture/rules target TCP **9999** ONLY |
| No global lockout | iptables always includes `--dport 9999 -s <IP>` |
| Protected ports | 22, 80, 443, 3000, 8000, 53 — NEVER touched |
| Auto-expiry | Blocked IPs auto-unblock after **20 seconds** |
| Graceful fallback | In-memory blocklist if iptables/sudo unavailable |

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Python >= 3.11 | Backend runtime |
| Wireshark / tshark | Packet capture (optional for demo mode) |
| Node.js >= 18 | Frontend runtime |

---

## Installation

### Backend

```bash
cd backend
pip install fastapi "uvicorn[standard]" pydantic
```

### Frontend (already scaffolded)

```bash
cd frontend
npm install
```

---

## Running the System

### Step 1 — Dummy TCP listener on port 9999 (Linux/macOS)

```bash
ncat -l 9999 --keep-open
# OR
python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 9999))
s.listen(100)
print('Listening on :9999')
while True:
    c, _ = s.accept()
    c.close()
"
```

### Step 2 — FastAPI backend

```bash
cd backend

# Linux with sudo (full iptables support):
sudo python safe_engine.py

# Windows / no-sudo (in-memory blocklist mode):
python safe_engine.py
```

Backend API: **http://localhost:8000**

### Step 3 — Next.js frontend

```bash
cd frontend
npm run dev
```

Dashboard: **http://localhost:3000**

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System health + iptables status |
| POST | `/api/unban` | Manually unban `{"ip": "..."}` |
| POST | `/api/simulate/syn` | Inject synthetic SYN flood (demo) |
| POST | `/api/simulate/bruteforce` | Inject synthetic brute-force (demo) |
| WS | `/ws/traffic` | Live JSON stream at 1s cadence |

---

## Detection Thresholds

| Attack Type | Threshold | Window |
|-------------|-----------|--------|
| L4 SYN Flood | > 15 SYN packets | Rolling 2 seconds |
| L7 HTTP Brute-Force | > 5 POST requests | Rolling 2 seconds |
| Block auto-expiry | TTL | **20 seconds** |

---

## Demo Mode (no Wireshark required)

Use the dashboard buttons or curl:

```bash
# Simulate SYN Flood
curl -X POST http://localhost:8000/api/simulate/syn

# Simulate Brute-Force
curl -X POST http://localhost:8000/api/simulate/bruteforce

# Manual unban
curl -X POST http://localhost:8000/api/unban \
     -H "Content-Type: application/json" \
     -d '{"ip":"127.42.0.1"}'
```

---

## Project Structure

```
cn/
├── backend/
│   ├── safe_engine.py        # FastAPI + tshark + detection + firewall
│   └── requirements.txt
└── frontend/
    ├── app/
    │   ├── page.tsx          # NetSentry dashboard (Recharts + Lucide)
    │   ├── layout.tsx        # Root layout (Inter font + metadata)
    │   └── globals.css       # Base styles + pastel palette + animations
    └── package.json
```
