"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  ShieldCheck,
  ShieldAlert,
  Wifi,
  WifiOff,
  Zap,
  Lock,
  Unlock,
  Activity,
  AlertTriangle,
  Clock,
  Server,
  Terminal,
  ChevronRight,
  Info,
} from "lucide-react";

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────
interface BlockedEntry {
  expiry: number;
  ttl_remaining: number;
}

interface Incident {
  ts: string;
  ip: string;
  reason: string;
  action: "BLOCKED" | "UNBANNED" | "UNBLOCKED";
}

interface TimelinePoint {
  time: string;
  syn_rate: number;
  post_rate: number;
  total_pps: number;
}

interface WSPayload {
  ts: string;
  blocked: Record<string, BlockedEntry>;
  incidents: Incident[];
  ip_metrics: Record<string, { syn_rate: number; post_rate: number; pps: number }>;
  timeline: TimelinePoint[];
  iptables_ok: boolean;
  isolated_port: number;
}

const API_BASE  = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const _wsBase   = API_BASE.replace(/^http/, "ws").replace(/^https/, "wss");
const WS_URL    = `${_wsBase}/ws/traffic`;

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
function fmtTime(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString("en-US", { hour12: false });
  } catch {
    return iso;
  }
}

function ActionBadge({ action }: { action: string }) {
  const cfg: Record<string, string> = {
    BLOCKED:   "bg-rose-100 text-rose-700 border border-rose-200",
    UNBANNED:  "bg-emerald-100 text-emerald-700 border border-emerald-200",
    UNBLOCKED: "bg-sky-100 text-sky-700 border border-sky-200",
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${cfg[action] ?? "bg-stone-100 text-stone-600"}`}>
      {action}
    </span>
  );
}

// ─────────────────────────────────────────────
// Initial Demo Data Generator
// ─────────────────────────────────────────────
function makeInitialDemoTimeline(): TimelinePoint[] {
  const now = Date.now();
  const pts: TimelinePoint[] = [];
  for (let i = 12; i >= 0; i--) {
    const t = new Date(now - i * 1000).toISOString();
    pts.push({
      time: t,
      syn_rate: Math.floor(Math.random() * 2) + 1,
      post_rate: Math.random() > 0.7 ? 1 : 0,
      total_pps: Math.floor(Math.random() * 3) + 3,
    });
  }
  return pts;
}

// ─────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────
export default function NetSentryPage() {
  const [data, setData]           = useState<WSPayload | null>(null);
  const [wsOnline, setWsOnline]   = useState(false);
  const [alert, setAlert]         = useState<string | null>(null);
  const [simLoading, setSimLoad]  = useState<string | null>(null);
  const alertTimer                = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevBlockedRef            = useRef<Set<string>>(new Set());
  const wsRef                     = useRef<WebSocket | null>(null);

  // Client-side fallback state for hosted demo mode
  const [demoState, setDemoState] = useState<WSPayload>(() => ({
    ts: new Date().toISOString(),
    blocked: {},
    incidents: [
      {
        ts: new Date(Date.now() - 35000).toISOString(),
        ip: "192.168.1.15",
        reason: "Normal baseline established",
        action: "UNBLOCKED",
      },
    ],
    ip_metrics: {
      "192.168.1.100": { syn_rate: 1, post_rate: 0, pps: 3 },
      "192.168.1.105": { syn_rate: 2, post_rate: 1, pps: 4 },
    },
    timeline: makeInitialDemoTimeline(),
    iptables_ok: false,
    isolated_port: 9999,
  }));

  // WebSocket connection
  const connectWS = useCallback(() => {
    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen  = () => setWsOnline(true);
      ws.onclose = () => {
        setWsOnline(false);
        setTimeout(connectWS, 4000);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (e) => {
        try {
          const payload: WSPayload = JSON.parse(e.data);
          setData(payload);

          // Detect newly blocked IPs → show alert banner
          const nowBlocked = new Set(Object.keys(payload.blocked));
          const newEntries = [...nowBlocked].filter((ip) => !prevBlockedRef.current.has(ip));
          if (newEntries.length > 0) {
            if (alertTimer.current) clearTimeout(alertTimer.current);
            setAlert(`⚠ Attack detected! IP(s) blocked: ${newEntries.join(", ")}`);
            alertTimer.current = setTimeout(() => setAlert(null), 4000);
          }
          prevBlockedRef.current = nowBlocked;
        } catch {}
      };
    } catch {
      setWsOnline(false);
    }
  }, []);

  useEffect(() => {
    connectWS();
    return () => {
      wsRef.current?.close();
      if (alertTimer.current) clearTimeout(alertTimer.current);
    };
  }, [connectWS]);

  // Demo simulator heartbeat (runs only when offline/backend not connected)
  useEffect(() => {
    if (wsOnline) return;

    const interval = setInterval(() => {
      setDemoState((prev) => {
        const now = Date.now();
        const nowIso = new Date().toISOString();

        // 1. Advance timeline
        const nextTimeline = [...prev.timeline.slice(-19), {
          time: nowIso,
          syn_rate: Math.floor(Math.random() * 3) + 1,
          post_rate: Math.random() > 0.6 ? 1 : 0,
          total_pps: Math.floor(Math.random() * 4) + 2,
        }];

        // 2. Decrement blocked TTLs
        const updatedBlocked: Record<string, BlockedEntry> = {};
        const unblockedIncidents: Incident[] = [];

        for (const [ip, entry] of Object.entries(prev.blocked)) {
          const rem = Math.max(0, Math.ceil((entry.expiry - now) / 1000));
          if (rem > 0) {
            updatedBlocked[ip] = { expiry: entry.expiry, ttl_remaining: rem };
          } else {
            unblockedIncidents.push({
              ts: nowIso,
              ip,
              reason: "20s TTL expired – firewall rule removed",
              action: "UNBLOCKED",
            });
          }
        }

        const nextIncidents = [...unblockedIncidents, ...prev.incidents].slice(0, 15);

        return {
          ...prev,
          ts: nowIso,
          blocked: updatedBlocked,
          incidents: nextIncidents,
          timeline: nextTimeline,
        };
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [wsOnline]);

  // Simulation trigger
  async function runSim(type: "syn" | "bruteforce") {
    setSimLoad(type);

    if (wsOnline) {
      try {
        await fetch(`${API_BASE}/api/simulate/${type}`, { method: "POST" });
      } catch {}
    } else {
      // In-browser demonstration simulator for hosted demo
      const fakeIp = type === "syn" ? "127.42.0.1" : "10.0.0.99";
      const reason = type === "syn" ? "SYN Flood (22 SYNs / 2.0s)" : "HTTP Brute-Force (7 POSTs / 2.0s)";
      const nowIso = new Date().toISOString();

      if (alertTimer.current) clearTimeout(alertTimer.current);
      setAlert(`⚠ Attack detected! IP blocked: ${fakeIp} (${reason})`);
      alertTimer.current = setTimeout(() => setAlert(null), 4500);

      setDemoState((prev) => {
        const nextBlocked = {
          ...prev.blocked,
          [fakeIp]: {
            expiry: Date.now() + 20000,
            ttl_remaining: 20,
          },
        };

        const newInc: Incident = {
          ts: nowIso,
          ip: fakeIp,
          reason,
          action: "BLOCKED",
        };

        const nextTimeline = [...prev.timeline.slice(-19), {
          time: nowIso,
          syn_rate: type === "syn" ? 22 : 2,
          post_rate: type === "bruteforce" ? 7 : 0,
          total_pps: type === "syn" ? 28 : 12,
        }];

        const nextMetrics = {
          ...prev.ip_metrics,
          [fakeIp]: {
            syn_rate: type === "syn" ? 22 : 1,
            post_rate: type === "bruteforce" ? 7 : 0,
            pps: type === "syn" ? 28 : 12,
          },
        };

        return {
          ...prev,
          blocked: nextBlocked,
          incidents: [newInc, ...prev.incidents].slice(0, 15),
          timeline: nextTimeline,
          ip_metrics: nextMetrics,
        };
      });
    }

    setTimeout(() => setSimLoad(null), 1500);
  }

  // Unban trigger
  async function unban(ip: string) {
    if (wsOnline) {
      try {
        await fetch(`${API_BASE}/api/unban`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip }),
        });
      } catch {}
    } else {
      setDemoState((prev) => {
        const nextBlocked = { ...prev.blocked };
        delete nextBlocked[ip];

        const newInc: Incident = {
          ts: new Date().toISOString(),
          ip,
          reason: "Manual admin unban via dashboard",
          action: "UNBANNED",
        };

        return {
          ...prev,
          blocked: nextBlocked,
          incidents: [newInc, ...prev.incidents].slice(0, 15),
        };
      });
    }
  }

  // Active view payload
  const currentData = wsOnline ? (data ?? demoState) : demoState;

  // Chart data: last 20 points
  const chartData = (currentData.timeline ?? []).map((p) => ({
    ...p,
    time: fmtTime(p.time),
  }));

  const blockedEntries = Object.entries(currentData.blocked ?? {});
  const incidents      = currentData.incidents ?? [];

  return (
    <div className="min-h-screen bg-stone-50 font-sans text-stone-800 antialiased selection:bg-rose-100 selection:text-rose-900">
      {/* ── Alert Banner ─────────────────────────────────────────────── */}
      {alert && (
        <div className="fixed top-0 inset-x-0 z-50 flex items-center justify-between gap-3 bg-rose-500 text-white px-6 py-3 shadow-lg animate-slide-down">
          <div className="flex items-center gap-2 max-w-7xl mx-auto w-full">
            <AlertTriangle className="text-white shrink-0 animate-bounce" size={18} />
            <p className="text-sm font-semibold tracking-wide flex-1">{alert}</p>
            <button
              onClick={() => setAlert(null)}
              className="text-white/80 hover:text-white font-bold text-xl px-2 leading-none"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* ── Top Header ───────────────────────────────────────────────── */}
      <header className="bg-white/95 backdrop-blur-md border-b border-stone-200/90 px-6 py-4 sticky top-0 z-40 shadow-xs">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-400 to-rose-500 flex items-center justify-center shadow-sm ring-2 ring-rose-100">
              <ShieldAlert size={20} className="text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-stone-900">NetSentry</h1>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold tracking-wider uppercase bg-stone-100 text-stone-600 border border-stone-200">
                  L4/L7 Defense
                </span>
              </div>
              <p className="text-xs text-stone-500 leading-tight">
                Real-Time Anomaly Detection & Firewall Mitigator · Port 9999
              </p>
            </div>
          </div>

          {/* Status + Simulation Buttons */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* WS / Mode status pill */}
            <div
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border shadow-2xs transition-all ${
                wsOnline
                  ? "bg-emerald-50 border-emerald-200 text-emerald-700"
                  : "bg-sky-50 border-sky-200 text-sky-700"
              }`}
              title={wsOnline ? "Connected to live FastAPI backend" : "Cloud Demo Mode (interactive simulation active)"}
            >
              {wsOnline ? (
                <>
                  <Wifi size={12} className="text-emerald-500 animate-pulse" />
                  <span>Live Backend</span>
                </>
              ) : (
                <>
                  <Activity size={12} className="text-sky-500 animate-pulse" />
                  <span>Interactive Demo Mode</span>
                </>
              )}
            </div>

            {/* iptables status */}
            <div
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border ${
                currentData.iptables_ok
                  ? "bg-emerald-50 border-emerald-200 text-emerald-700"
                  : "bg-stone-100 border-stone-200 text-stone-600"
              }`}
            >
              <Terminal size={12} />
              {currentData.iptables_ok ? "iptables Active" : "In-Memory Mitigator"}
            </div>

            {/* Sim buttons */}
            <button
              onClick={() => runSim("syn")}
              disabled={simLoading === "syn"}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-rose-500 hover:bg-rose-600 active:scale-95 text-white transition-all shadow-sm hover:shadow disabled:opacity-60 cursor-pointer"
            >
              <Zap size={13} className={simLoading === "syn" ? "animate-spin" : ""} />
              {simLoading === "syn" ? "Injecting Attack…" : "Simulate SYN Flood"}
            </button>
            <button
              onClick={() => runSim("bruteforce")}
              disabled={simLoading === "bruteforce"}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-amber-500 hover:bg-amber-600 active:scale-95 text-white transition-all shadow-sm hover:shadow disabled:opacity-60 cursor-pointer"
            >
              <Lock size={13} className={simLoading === "bruteforce" ? "animate-spin" : ""} />
              {simLoading === "bruteforce" ? "Injecting Attack…" : "Simulate Brute-Force"}
            </button>
          </div>
        </div>
      </header>

      {/* ── Main Grid ────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">

        {/* Demo Mode Notice Banner (when backend not connected) */}
        {!wsOnline && (
          <div className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-sky-50 border border-sky-200 text-sky-800 text-xs">
            <Info size={16} className="text-sky-500 shrink-0" />
            <p className="flex-1">
              <strong>Interactive Cloud Demo:</strong> You are viewing NetSentry in web preview mode. Click <strong>Simulate SYN Flood</strong> or <strong>Simulate Brute-Force</strong> to watch the anomaly detection, live rolling telemetry spike, and auto-expiring 20s firewall mitigation in real time.
            </p>
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            {
              label: "Blocked IPs",
              value: blockedEntries.length,
              icon: <ShieldAlert size={18} />,
              color: "rose",
            },
            {
              label: "Total Incidents",
              value: incidents.length,
              icon: <AlertTriangle size={18} />,
              color: "amber",
            },
            {
              label: "Protected Port",
              value: currentData.isolated_port ?? 9999,
              icon: <Server size={18} />,
              color: "sky",
            },
            {
              label: "Telemetry Window",
              value: `${chartData.length}s`,
              icon: <Activity size={18} />,
              color: "emerald",
            },
          ].map((s) => (
            <div
              key={s.label}
              className="bg-white border border-stone-200/80 rounded-2xl p-4 shadow-sm hover:shadow-md transition-shadow"
            >
              <div className={`w-9 h-9 rounded-xl flex items-center justify-center mb-3 ${
                s.color === "rose"    ? "bg-rose-100 text-rose-500"    :
                s.color === "amber"   ? "bg-amber-100 text-amber-500"  :
                s.color === "sky"     ? "bg-sky-100 text-sky-500"      :
                                        "bg-emerald-100 text-emerald-600"
              }`}>
                {s.icon}
              </div>
              <p className="text-2xl font-bold tracking-tight text-stone-900">{s.value}</p>
              <p className="text-xs text-stone-500 mt-0.5 font-medium">{s.label}</p>
            </div>
          ))}
        </div>

        {/* ── Live Telemetry Chart ──────────────────────────────────── */}
        <div className="bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between gap-2 mb-4">
            <div className="flex items-center gap-2">
              <Activity size={16} className="text-sky-500" />
              <h2 className="text-sm font-semibold text-stone-800">Live Traffic Telemetry · 20s Rolling Window</h2>
            </div>
            <div className="flex items-center gap-3 text-xs text-stone-500">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-400 inline-block" /> SYN Rate
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" /> POST Rate
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-sky-400 inline-block" /> Total PPS
              </span>
            </div>
          </div>
          {chartData.length > 0 ? (
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="synGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#fb7185" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#fb7185" stopOpacity={0.03} />
                    </linearGradient>
                    <linearGradient id="postGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#fbbf24" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#fbbf24" stopOpacity={0.03} />
                    </linearGradient>
                    <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#38bdf8" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.03} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f0ef" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#a8a29e" }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "#a8a29e" }} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{
                      background: "#fff",
                      border: "1px solid #e7e5e4",
                      borderRadius: "12px",
                      fontSize: "12px",
                      boxShadow: "0 4px 16px rgba(0,0,0,0.06)",
                    }}
                  />
                  <Legend wrapperStyle={{ display: "none" }} />
                  <Area type="monotone" dataKey="syn_rate"  name="SYN Rate"  stroke="#fb7185" strokeWidth={2.5} fill="url(#synGrad)"  dot={false} />
                  <Area type="monotone" dataKey="post_rate" name="POST Rate" stroke="#fbbf24" strokeWidth={2.5} fill="url(#postGrad)" dot={false} />
                  <Area type="monotone" dataKey="total_pps" name="Total PPS" stroke="#38bdf8" strokeWidth={2.5} fill="url(#ppsGrad)"  dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-60 flex flex-col items-center justify-center text-stone-400 gap-2">
              <Activity size={32} className="opacity-30 animate-pulse" />
              <p className="text-sm">Connecting to telemetry feed…</p>
            </div>
          )}
        </div>

        {/* ── Two-Column Bottom Row ──────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

          {/* Active Firewall Drops */}
          <div className="lg:col-span-2 bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className="text-rose-500" />
                <h2 className="text-sm font-semibold text-stone-800">Active Firewall Drops</h2>
              </div>
              <span className="text-xs bg-rose-50 text-rose-600 border border-rose-200 px-2.5 py-0.5 rounded-full font-medium">
                Auto-TTL: 20s
              </span>
            </div>

            {blockedEntries.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center py-10 text-stone-400 gap-3">
                <div className="w-14 h-14 rounded-2xl bg-emerald-50 border border-emerald-100 flex items-center justify-center">
                  <ShieldCheck size={28} className="text-emerald-500" />
                </div>
                <div className="text-center">
                  <p className="text-sm font-semibold text-emerald-700">No Active Blocks</p>
                  <p className="text-xs text-stone-400 mt-0.5">Port 9999 traffic clean – zero drop rules</p>
                </div>
              </div>
            ) : (
              <div className="space-y-3 flex-1">
                {blockedEntries.map(([ip, entry]) => (
                  <div
                    key={ip}
                    className="flex items-center justify-between p-3.5 rounded-xl border border-rose-200/80 bg-rose-50/50 hover:bg-rose-50 transition-colors"
                  >
                    <div className="space-y-1">
                      <span className="font-mono text-sm font-bold text-stone-900 block">{ip}</span>
                      <div className="flex items-center gap-1.5 text-xs text-rose-600 font-medium">
                        <Clock size={12} />
                        <span>Expires in {entry.ttl_remaining}s</span>
                      </div>
                    </div>
                    <button
                      onClick={() => unban(ip)}
                      className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-rose-200 text-rose-600 hover:bg-rose-100 active:scale-95 transition-all shadow-2xs cursor-pointer"
                    >
                      <Unlock size={12} />
                      Unban
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Security Incident Log */}
          <div className="lg:col-span-3 bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle size={16} className="text-amber-500" />
                <h2 className="text-sm font-semibold text-stone-800">Security Incident Log</h2>
              </div>
              <span className="text-xs text-stone-400 font-medium">Audit Trail</span>
            </div>

            {incidents.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center py-10 text-stone-400 gap-2">
                <Activity size={28} className="opacity-30 animate-pulse" />
                <p className="text-sm">No incidents recorded yet</p>
              </div>
            ) : (
              <div className="overflow-x-auto -mx-1 flex-1">
                <table className="w-full text-xs text-left">
                  <thead>
                    <tr className="text-stone-400 uppercase tracking-wider text-[11px] border-b border-stone-100">
                      <th className="pb-2 px-3 font-semibold">Timestamp</th>
                      <th className="pb-2 px-3 font-semibold">Source IP</th>
                      <th className="pb-2 px-3 font-semibold">Anomaly Reason</th>
                      <th className="pb-2 px-3 font-semibold text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-100">
                    {incidents.slice(0, 8).map((inc, i) => (
                      <tr key={i} className="hover:bg-stone-50/80 transition-colors">
                        <td className="py-2.5 px-3 font-mono text-stone-500 whitespace-nowrap">{fmtTime(inc.ts)}</td>
                        <td className="py-2.5 px-3 font-mono font-bold text-stone-800">{inc.ip}</td>
                        <td className="py-2.5 px-3 text-stone-600 max-w-[200px] truncate">{inc.reason}</td>
                        <td className="py-2.5 px-3 text-right">
                          <ActionBadge action={inc.action} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* IP Metrics Table */}
        {Object.keys(currentData.ip_metrics).length > 0 && (
          <div className="bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2">
                <Server size={16} className="text-sky-500" />
                <h2 className="text-sm font-semibold text-stone-800">Per-IP Traffic Rates & Inspection</h2>
              </div>
              <span className="text-xs text-stone-400">Layer 4 / Layer 7 Thresholds</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="text-stone-400 uppercase tracking-wider text-[11px] border-b border-stone-100">
                    <th className="pb-2 pr-4 font-semibold">Source IP</th>
                    <th className="pb-2 pr-4 font-semibold">SYN Rate (L4 Threshold &gt; 15/2s)</th>
                    <th className="pb-2 pr-4 font-semibold">POST Rate (L7 Threshold &gt; 5/2s)</th>
                    <th className="pb-2 font-semibold">Mitigation Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-stone-50">
                  {Object.entries(currentData.ip_metrics).map(([ip, m]) => {
                    const isBlocked = ip in (currentData.blocked ?? {});
                    return (
                      <tr key={ip} className={`hover:bg-stone-50 transition-colors ${isBlocked ? "bg-rose-50/40" : ""}`}>
                        <td className="py-3 pr-4 font-mono font-bold text-stone-800">{ip}</td>
                        <td className="py-3 pr-4">
                          <div className="flex items-center gap-2">
                            <div className="h-2 rounded-full bg-rose-100 w-24 overflow-hidden">
                              <div
                                className="h-full bg-rose-500 rounded-full transition-all duration-300"
                                style={{ width: `${Math.min(100, (m.syn_rate / 20) * 100)}%` }}
                              />
                            </div>
                            <span className="font-mono text-rose-600 font-semibold">{m.syn_rate}/s</span>
                          </div>
                        </td>
                        <td className="py-3 pr-4">
                          <div className="flex items-center gap-2">
                            <div className="h-2 rounded-full bg-amber-100 w-24 overflow-hidden">
                              <div
                                className="h-full bg-amber-500 rounded-full transition-all duration-300"
                                style={{ width: `${Math.min(100, (m.post_rate / 8) * 100)}%` }}
                              />
                            </div>
                            <span className="font-mono text-amber-600 font-semibold">{m.post_rate}/s</span>
                          </div>
                        </td>
                        <td className="py-3">
                          {isBlocked ? (
                            <span className="px-2.5 py-0.5 bg-rose-100 text-rose-700 border border-rose-200 rounded-full text-xs font-semibold flex items-center gap-1 w-fit">
                              <ShieldAlert size={11} /> Dropped (Active Block)
                            </span>
                          ) : (
                            <span className="px-2.5 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full text-xs font-semibold flex items-center gap-1 w-fit">
                              <ShieldCheck size={11} /> Clean (Passing)
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="text-center text-xs text-stone-400 py-4 flex items-center justify-center gap-1.5 border-t border-stone-200/50">
          <ChevronRight size={12} />
          NetSentry · L4/L7 Anomaly Detection Engine · Capture Target: <code className="bg-stone-100 px-1 py-0.5 rounded font-mono text-stone-600">lo:tcp/9999</code>
          · 20s Auto-Expiry Mitigator · Protected system ports: 22, 80, 443
        </footer>
      </main>
    </div>
  );
}
