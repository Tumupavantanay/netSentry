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

const API_BASE = "http://localhost:8000";
const WS_URL   = "ws://localhost:8000/ws/traffic";

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

  // WebSocket connection
  const connectWS = useCallback(() => {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen  = () => setWsOnline(true);
    ws.onclose = () => {
      setWsOnline(false);
      setTimeout(connectWS, 3000); // auto-reconnect
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
  }, []);

  useEffect(() => {
    connectWS();
    return () => {
      wsRef.current?.close();
      if (alertTimer.current) clearTimeout(alertTimer.current);
    };
  }, [connectWS]);

  // Simulation handlers
  async function runSim(type: "syn" | "bruteforce") {
    setSimLoad(type);
    try {
      await fetch(`${API_BASE}/api/simulate/${type}`, { method: "POST" });
    } catch {}
    setTimeout(() => setSimLoad(null), 2000);
  }

  async function unban(ip: string) {
    await fetch(`${API_BASE}/api/unban`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
  }

  // Chart data: last 20 points
  const chartData = (data?.timeline ?? []).map((p) => ({
    ...p,
    time: fmtTime(p.time),
  }));

  const blockedEntries = Object.entries(data?.blocked ?? {});
  const incidents      = data?.incidents ?? [];

  return (
    <div className="min-h-screen bg-stone-50 font-sans text-stone-800">
      {/* ── Alert Banner ─────────────────────────────────────────────── */}
      {alert && (
        <div className="fixed top-0 inset-x-0 z-50 flex items-center gap-3 bg-rose-50 border-b border-rose-200 px-6 py-3 shadow-md animate-slide-down">
          <AlertTriangle className="text-rose-500 shrink-0" size={18} />
          <p className="text-rose-700 text-sm font-medium flex-1">{alert}</p>
          <button onClick={() => setAlert(null)} className="text-rose-400 hover:text-rose-600 text-lg leading-none">×</button>
        </div>
      )}

      {/* ── Top Header ───────────────────────────────────────────────── */}
      <header className="bg-white border-b border-stone-200 px-6 py-4 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-rose-400 to-rose-500 flex items-center justify-center shadow-sm">
              <ShieldAlert size={18} className="text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-stone-900">NetSentry</h1>
              <p className="text-xs text-stone-500 leading-tight">Real-Time L4/L7 Anomaly Detection · Wireshark/tshark · Port 9999</p>
            </div>
          </div>

          {/* Status + Simulation Buttons */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* WS status pill */}
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border ${
              wsOnline
                ? "bg-emerald-50 border-emerald-200 text-emerald-700"
                : "bg-rose-50 border-rose-200 text-rose-600"
            }`}>
              {wsOnline ? <Wifi size={12} /> : <WifiOff size={12} />}
              {wsOnline ? "Live" : "Offline"}
            </div>

            {/* iptables status */}
            {data && (
              <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border ${
                data.iptables_ok
                  ? "bg-sky-50 border-sky-200 text-sky-700"
                  : "bg-amber-50 border-amber-200 text-amber-700"
              }`}>
                <Terminal size={12} />
                {data.iptables_ok ? "iptables Active" : "In-Memory Mode"}
              </div>
            )}

            {/* Sim buttons */}
            <button
              onClick={() => runSim("syn")}
              disabled={simLoading === "syn"}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-rose-500 hover:bg-rose-600 active:scale-95 text-white transition-all shadow-sm disabled:opacity-60"
            >
              <Zap size={13} />
              {simLoading === "syn" ? "Simulating…" : "Test SYN Flood"}
            </button>
            <button
              onClick={() => runSim("bruteforce")}
              disabled={simLoading === "bruteforce"}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-amber-500 hover:bg-amber-600 active:scale-95 text-white transition-all shadow-sm disabled:opacity-60"
            >
              <Lock size={13} />
              {simLoading === "bruteforce" ? "Simulating…" : "Test Brute-Force"}
            </button>
          </div>
        </div>
      </header>

      {/* ── Main Grid ────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">

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
              label: "Isolated Port",
              value: data?.isolated_port ?? 9999,
              icon: <Server size={18} />,
              color: "sky",
            },
            {
              label: "Live Timeline",
              value: `${chartData.length}s`,
              icon: <Activity size={18} />,
              color: "emerald",
            },
          ].map((s) => (
            <div key={s.label} className="bg-white border border-stone-200/80 rounded-2xl p-4 shadow-sm">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-3 ${
                s.color === "rose"    ? "bg-rose-100 text-rose-500"    :
                s.color === "amber"   ? "bg-amber-100 text-amber-500"  :
                s.color === "sky"     ? "bg-sky-100 text-sky-500"      :
                                        "bg-emerald-100 text-emerald-600"
              }`}>
                {s.icon}
              </div>
              <p className="text-2xl font-bold text-stone-900">{s.value}</p>
              <p className="text-xs text-stone-500 mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>

        {/* ── Live Telemetry Chart ──────────────────────────────────── */}
        <div className="bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Activity size={16} className="text-sky-500" />
            <h2 className="text-sm font-semibold text-stone-700">Live Traffic Telemetry · 20s Rolling Window</h2>
          </div>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
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
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f0ef" />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#a8a29e" }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "#a8a29e" }} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    background: "#fff",
                    border: "1px solid #e7e5e4",
                    borderRadius: "10px",
                    fontSize: "12px",
                    boxShadow: "0 4px 12px rgba(0,0,0,0.06)",
                  }}
                />
                <Legend wrapperStyle={{ fontSize: "12px", paddingTop: "12px" }} />
                <Area type="monotone" dataKey="syn_rate"  name="SYN Rate"  stroke="#fb7185" strokeWidth={2} fill="url(#synGrad)"  dot={false} />
                <Area type="monotone" dataKey="post_rate" name="POST Rate" stroke="#fbbf24" strokeWidth={2} fill="url(#postGrad)" dot={false} />
                <Area type="monotone" dataKey="total_pps" name="Total PPS" stroke="#38bdf8" strokeWidth={2} fill="url(#ppsGrad)"  dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-60 flex flex-col items-center justify-center text-stone-400 gap-2">
              <Activity size={32} className="opacity-30 animate-pulse" />
              <p className="text-sm">Waiting for traffic data…</p>
            </div>
          )}
        </div>

        {/* ── Bottom Row: Firewall Drops + Incident Log ─────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

          {/* Active Firewall Drops */}
          <div className="lg:col-span-2 bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className="text-rose-500" />
                <h2 className="text-sm font-semibold text-stone-700">Active Firewall Drops</h2>
              </div>
              <span className="text-xs bg-rose-50 text-rose-600 border border-rose-200 px-2 py-0.5 rounded-full font-medium">
                TTL: 20s
              </span>
            </div>

            {blockedEntries.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-stone-400 gap-3">
                <div className="w-14 h-14 rounded-full bg-emerald-50 flex items-center justify-center">
                  <ShieldCheck size={28} className="text-emerald-500" />
                </div>
                <p className="text-sm font-medium text-emerald-600">No active blocks</p>
                <p className="text-xs text-stone-400">All clear – network is clean</p>
              </div>
            ) : (
              <ul className="space-y-2">
                {blockedEntries.map(([ip, info]) => (
                  <li key={ip} className="flex items-center justify-between gap-3 p-3 bg-rose-50 border border-rose-100 rounded-xl">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="w-2 h-2 rounded-full bg-rose-400 animate-pulse shrink-0" />
                      <span className="text-sm font-mono font-semibold text-rose-800 truncate">{ip}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="flex items-center gap-1 text-xs text-rose-600">
                        <Clock size={11} />
                        {info.ttl_remaining}s
                      </div>
                      <button
                        onClick={() => unban(ip)}
                        className="flex items-center gap-1 text-xs bg-white border border-stone-200 hover:border-emerald-300 hover:text-emerald-700 text-stone-600 px-2 py-1 rounded-lg transition-colors"
                      >
                        <Unlock size={11} />
                        Unban
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Security Incident Log */}
          <div className="lg:col-span-3 bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle size={16} className="text-amber-500" />
              <h2 className="text-sm font-semibold text-stone-700">Security Incident Log</h2>
              <span className="ml-auto text-xs text-stone-400">Latest 8 events</span>
            </div>

            {incidents.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-stone-400 gap-2">
                <Activity size={28} className="opacity-30 animate-pulse" />
                <p className="text-sm">No incidents recorded yet</p>
              </div>
            ) : (
              <div className="overflow-x-auto -mx-1">
                <table className="w-full text-xs text-left">
                  <thead>
                    <tr className="text-stone-400 uppercase tracking-wide">
                      <th className="pb-2 px-2 font-medium">Timestamp</th>
                      <th className="pb-2 px-2 font-medium">Source IP</th>
                      <th className="pb-2 px-2 font-medium">Anomaly Reason</th>
                      <th className="pb-2 px-2 font-medium text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-100">
                    {incidents.map((inc, i) => (
                      <tr key={i} className="hover:bg-stone-50 transition-colors">
                        <td className="py-2.5 px-2 font-mono text-stone-500 whitespace-nowrap">{fmtTime(inc.ts)}</td>
                        <td className="py-2.5 px-2 font-mono font-semibold text-stone-800">{inc.ip}</td>
                        <td className="py-2.5 px-2 text-stone-600 max-w-[180px] truncate">{inc.reason}</td>
                        <td className="py-2.5 px-2 text-right">
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
        {data && Object.keys(data.ip_metrics).length > 0 && (
          <div className="bg-white border border-stone-200/80 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center gap-2 mb-4">
              <Server size={16} className="text-sky-500" />
              <h2 className="text-sm font-semibold text-stone-700">Per-IP Traffic Metrics</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="text-stone-400 uppercase tracking-wide border-b border-stone-100">
                    <th className="pb-2 pr-4 font-medium">Source IP</th>
                    <th className="pb-2 pr-4 font-medium">SYN Rate</th>
                    <th className="pb-2 pr-4 font-medium">POST Rate</th>
                    <th className="pb-2 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-stone-50">
                  {Object.entries(data.ip_metrics).map(([ip, m]) => {
                    const isBlocked = ip in (data.blocked ?? {});
                    return (
                      <tr key={ip} className={`hover:bg-stone-50 transition-colors ${isBlocked ? "bg-rose-50/40" : ""}`}>
                        <td className="py-2.5 pr-4 font-mono font-semibold text-stone-800">{ip}</td>
                        <td className="py-2.5 pr-4">
                          <div className="flex items-center gap-1.5">
                            <div className="h-1.5 rounded-full bg-rose-200 w-16 overflow-hidden">
                              <div className="h-full bg-rose-400 rounded-full" style={{ width: `${Math.min(100, (m.syn_rate / 20) * 100)}%` }} />
                            </div>
                            <span className="text-rose-600 font-medium">{m.syn_rate}</span>
                          </div>
                        </td>
                        <td className="py-2.5 pr-4">
                          <div className="flex items-center gap-1.5">
                            <div className="h-1.5 rounded-full bg-amber-200 w-16 overflow-hidden">
                              <div className="h-full bg-amber-400 rounded-full" style={{ width: `${Math.min(100, (m.post_rate / 8) * 100)}%` }} />
                            </div>
                            <span className="text-amber-600 font-medium">{m.post_rate}</span>
                          </div>
                        </td>
                        <td className="py-2.5">
                          {isBlocked ? (
                            <span className="px-2 py-0.5 bg-rose-100 text-rose-700 border border-rose-200 rounded-full text-xs font-semibold flex items-center gap-1 w-fit">
                              <ShieldAlert size={10} /> Blocked
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full text-xs font-semibold flex items-center gap-1 w-fit">
                              <ShieldCheck size={10} /> Clean
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
        <footer className="text-center text-xs text-stone-400 py-4 flex items-center justify-center gap-1.5">
          <ChevronRight size={12} />
          NetSentry · L4/L7 Anomaly Detection · Capture Interface: <code className="bg-stone-100 px-1 py-0.5 rounded">lo:tcp/9999</code>
          · Auto-block TTL: 20s · No system ports affected
        </footer>
      </main>

      <style jsx global>{`
        @keyframes slide-down {
          from { transform: translateY(-100%); opacity: 0; }
          to   { transform: translateY(0);     opacity: 1; }
        }
        .animate-slide-down { animation: slide-down 0.3s ease-out; }
      `}</style>
    </div>
  );
}
